# ruff: noqa: F821
"""Fixed target helper for owned p11-kit policy and consolidated native exports."""

import ctypes
import re
import secrets
import shutil

from _emudhra_helpers.p11_native import P11_EXPORTS, p11_generate, p11_output_tree
from _emudhra_helpers.p11_policy import (
    POLICY_NAME,
    p11_denied,
    p11_encode,
    p11_extra_anchors,
    p11_materialize,
    p11_semantics,
    p11_source_view,
    p11_verify_denials,
    p11_verify_transition,
)

P11_FILE_PERFORM = perform
P11_FILES = tuple(
    name
    for name, format, _, _ in P11_EXPORTS
    if format != "pem-directory-hash" and not name.startswith("audit/")
)


def p11_meta(path):
    info = os.lstat(path)
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "attrs": {
            name: base64.b64encode(os.getxattr(path, name, follow_symlinks=False)).decode()
            for name in os.listxattr(path, follow_symlinks=False)
        },
    }


def p11_set_meta(path, value):
    symbolic = stat.S_ISLNK(os.lstat(path).st_mode)
    if not symbolic:
        # This function only receives private staged objects. Native exports are
        # read-only; owner-write permission is needed to restore user xattrs.
        os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | 0o200)
    os.chown(path, value["uid"], value["gid"], follow_symlinks=False)
    attrs = value["attrs"]
    for name in set(os.listxattr(path, follow_symlinks=False)) - attrs.keys():
        os.removexattr(path, name, follow_symlinks=False)
    for name, data in attrs.items():
        os.setxattr(path, name, base64.b64decode(data, validate=True), follow_symlinks=False)
    if not symbolic:
        os.chmod(path, value["mode"])
    if p11_meta(path) != value:
        raise ValueError("Cannot preserve p11-kit output metadata exactly")
    if not symbolic:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def p11_output_metadata(root):
    result = {}
    for name in P11_FILES:
        path = safe_path(os.path.join(root, name))
        read(path)
        result[name] = p11_meta(path)
    hashed = safe_path(os.path.join(root, "pem/directory-hash"))
    if not os.path.isdir(hashed):
        raise ValueError("p11-kit hashed output directory must exist")
    result["hash-directory"] = p11_meta(hashed)
    compatibility = os.path.join(hashed, "ca-certificates.crt")
    if not os.path.islink(compatibility):
        raise ValueError("p11-kit hash directory requires native compatibility links")
    result["hash-link"] = p11_meta(compatibility)
    for name in os.listdir(hashed):
        path = os.path.join(hashed, name)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            if p11_meta(path) != result["hash-link"]:
                raise ValueError("Nonuniform p11-kit hash-link metadata is unsupported")
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            if p11_meta(path) != result["pem/tls-ca-bundle.pem"]:
                raise ValueError("Hash certificates must share the TLS bundle's metadata")
        else:
            raise ValueError("Unsupported object in p11-kit hash directory")
    return result


def p11_snapshot(request):
    path = safe_path(request["path"])
    options = request["p11"]
    if path != os.path.join(options["source_dirs"][0], POLICY_NAME):
        raise ValueError("p11-kit requires its owned top-level policy file")
    policy, _ = read(path)  # Pre-existing file also supplies owner/ACL/SELinux metadata.
    sources, total, count = [], len(policy), 0
    for i, root in enumerate(options["source_dirs"]):
        safe_path(root)
        if not os.path.isdir(root):
            raise ValueError("p11-kit source directories must exist")
        entries = {}

        def fail_walk(error):
            raise error

        for current, directories, names in os.walk(root, onerror=fail_walk):
            for directory in list(directories):
                directory_path = safe_path(os.path.join(current, directory))
                if current == root and i == 0 and directory == POLICY_NAME + ".emudhra-work":
                    directories.remove(directory)
                elif current != root or directory not in ("anchors", "blocklist", "blacklist"):
                    raise ValueError("Unsupported p11-kit source subdirectory")
                if not os.path.isdir(directory_path):
                    raise ValueError("Invalid p11-kit source directory")
            for name in sorted(names):
                if i == 0 and current == root and name == POLICY_NAME:
                    continue
                candidate = safe_path(os.path.join(current, name))
                data, _ = read(candidate)
                total += len(data)
                count += 1
                if total > MAX_BYTES or count > 4096:
                    raise ValueError("p11-kit source snapshot exceeds limits")
                entries[os.path.relpath(candidate, root)] = base64.b64encode(data).decode()
        sources.append(entries)
    value = {
        "policy": base64.b64encode(policy).decode(),
        "sources": sources,
        "metadata": p11_output_metadata(safe_path(options["output_dir"])),
    }
    # Bind the target's native interpretation as well as raw sources. Controllers
    # with different p11-kit behavior must not silently miss target certificates.
    with tempfile.TemporaryDirectory(prefix="emudhra-p11-snapshot-") as temporary:
        try:
            _, files, _ = p11_stage(request, p11_encode(value), temporary, "view", check_view=False)
            value["source_view"] = p11_source_view(files)
        finally:
            p11_clean(temporary)
    result = p11_encode(value)
    if len(result) > MAX_BYTES:
        raise ValueError("p11-kit snapshot exceeds size limit")
    return result


def p11_actual(root):
    files = {name: read(safe_path(os.path.join(root, name)))[0] for name in P11_FILES}
    hashed, links = p11_output_tree(os.path.join(root, "pem/directory-hash"), "pem/directory-hash/")
    files.update(hashed)
    return files, links


def p11_stage(request, snapshot, workspace, label, *, check_view=True):
    source = os.path.join(workspace, label + "-sources")
    os.mkdir(source, 0o700)
    directories = p11_materialize(json.loads(snapshot), source)
    output = os.path.join(workspace, label + "-exports")
    options = request["p11"]
    p11_generate(options["trust_binary"], options["module_path"], directories, output)
    files, links = p11_output_tree(output)
    p11_verify_denials(files)
    if check_view and p11_source_view(files) != json.loads(snapshot)["source_view"]:
        raise ValueError("Target p11-kit interpretation differs from the planned source view")
    return output, files, links


def p11_clean(root):
    # Private staging only; never follow links while making generated dirs removable.
    for current, directories, _ in os.walk(root, followlinks=False):
        for name in directories:
            path = os.path.join(current, name)
            if not os.path.islink(path):
                os.chmod(path, 0o700)


def p11_rename(left, right, flags):
    library = ctypes.CDLL(None, use_errno=True)
    try:
        exchange = library.renameat2
    except AttributeError as error:
        raise ValueError("p11-kit output replacement requires Linux renameat2") from error
    exchange.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    exchange.restype = ctypes.c_int
    if exchange(-100, os.fsencode(left), -100, os.fsencode(right), flags) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "Cannot atomically exchange p11-kit output directories")


def p11_exchange(left, right):
    p11_rename(left, right, 2)


def p11_check_hash(actual, expected_hash, expected_identity):
    current = os.lstat(actual)
    if (current.st_dev, current.st_ino) != expected_identity or p11_output_tree(
        actual, "pem/directory-hash/"
    ) != expected_hash:
        raise ValueError("Concurrent p11-kit hash-directory update detected")


def p11_preflight_files(stage, root, metadata, actual_sem, desired_sem):
    for name in P11_FILES:
        if actual_sem[name] == desired_sem[name]:
            continue
        target = safe_path(os.path.join(root, name))
        # Exercise real parent-directory permissions and the writer workspace
        # before policy mutation. These probes contain no certificates.
        fd, probe = tempfile.mkstemp(prefix=".emudhra-preflight-", dir=os.path.dirname(target))
        os.close(fd)
        os.unlink(probe)
        with lock(target) as workspace:
            fd, probe = tempfile.mkstemp(prefix="pending-", dir=workspace)
            os.close(fd)
            os.unlink(probe)
        p11_set_meta(os.path.join(stage, name), metadata[name])


def p11_prepare_hash(stage, root, metadata, workspace):
    hashed = os.path.join(stage, "pem/directory-hash")
    actual = os.path.join(root, "pem/directory-hash")
    if os.stat(hashed).st_dev != os.stat(actual).st_dev or os.path.ismount(actual):
        raise ValueError("p11-kit hash directory must be on the staging filesystem, not a mount")
    with open("/proc/self/mountinfo") as mounts:
        if any(line.split()[4] == actual for line in mounts):
            raise ValueError("Mounted p11-kit hash directories are unsupported")
    os.chmod(hashed, 0o700)
    for name in os.listdir(hashed):
        path = os.path.join(hashed, name)
        p11_set_meta(
            path,
            metadata["hash-link"] if os.path.islink(path) else metadata["pem/tls-ca-bundle.pem"],
        )
    p11_set_meta(hashed, metadata["hash-directory"])
    # Probe renameat2 support using unrelated temporary directories, before writes.
    a, b = os.path.join(workspace, "exchange-a"), os.path.join(workspace, "exchange-b")
    os.mkdir(a)
    os.mkdir(b)
    p11_exchange(a, b)
    os.rmdir(a)
    os.rmdir(b)


def p11_cleanup_pending(root, workspace):
    marker = os.path.join(workspace, "hash-pending.json")
    if not os.path.lexists(marker):
        return
    saved = json.loads(read(safe_path(marker))[0])
    if not re.fullmatch(r"\.emudhra-hash-[A-Za-z0-9_-]+", saved["name"]):
        raise ValueError("Unsafe p11-kit staging record")
    candidate = os.path.join(root, "pem", saved["name"])
    if os.path.lexists(candidate):
        info = os.lstat(candidate)
        if not stat.S_ISDIR(info.st_mode) or [info.st_dev, info.st_ino] not in saved["identities"]:
            raise ValueError("p11-kit staged-directory identity conflict")
        os.chmod(candidate, 0o700)
        p11_clean(candidate)
        shutil.rmtree(candidate)
    os.unlink(marker)
    for parent in (os.path.join(root, "pem"), workspace):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def p11_cleanup_generations(workspace):
    for name in os.listdir(workspace):
        if not name.startswith("generation-"):
            continue
        path = os.path.join(workspace, name)
        info = os.lstat(path)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("Unsafe abandoned p11-kit staging directory")
        p11_clean(path)
        shutil.rmtree(path)


def p11_swap_hash(stage, root, workspace, metadata, expected_hash, expected_identity):
    global WRITE_STARTED
    source = os.path.join(stage, "pem/directory-hash")
    actual = os.path.join(root, "pem/directory-hash")
    pending = os.path.join(os.path.dirname(actual), ".emudhra-hash-" + secrets.token_hex(16))
    identities = [[os.stat(p).st_dev, os.stat(p).st_ino] for p in (source, actual)]
    marker = os.path.join(workspace, "hash-pending.json")
    descriptor, marker_pending = tempfile.mkstemp(prefix="pending-", dir=workspace)
    with os.fdopen(descriptor, "wb") as file:
        file.write(p11_encode({"name": os.path.basename(pending), "identities": identities}))
        file.flush()
        os.fsync(file.fileno())
    os.replace(marker_pending, marker)
    fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        # Cross-parent directory moves need owner-write access for '..'. Move the
        # private copy first; the final exchange shares a parent and does not
        # require changing permissions on the live read-only CApath directory.
        os.chmod(source, metadata["hash-directory"]["mode"] | 0o200)
        p11_rename(source, pending, 1)  # RENAME_NOREPLACE
        p11_set_meta(pending, metadata["hash-directory"])
        p11_check_hash(actual, expected_hash, expected_identity)
        WRITE_STARTED = True
        p11_exchange(pending, actual)
        fd = os.open(os.path.dirname(actual), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        p11_cleanup_pending(root, workspace)


def p11_install(
    request,
    stage,
    files,
    links,
    snapshot,
    workspace,
    expected_files,
    expected_hash,
    expected_identity,
):
    global WRITE_STARTED
    root = request["p11"]["output_dir"]
    wrote = WRITE_STARTED
    expected_sem = p11_semantics(expected_files, expected_hash[1])
    desired_sem = p11_semantics(files, links)
    try:
        for name in P11_FILES:
            path = safe_path(os.path.join(root, name))
            old, _ = read(path)
            if (
                old != expected_files[name]
                or p11_meta(path) != json.loads(snapshot)["metadata"][name]
            ):
                raise ValueError("Concurrent p11-kit generated-file update detected")
            if expected_sem[name] == desired_sem[name]:
                continue
            P11_FILE_PERFORM(
                {
                    "operation": "replace",
                    "path": path,
                    "expected_sha256": sha(old),
                    "data": base64.b64encode(files[name]).decode(),
                },
                allow_empty=True,
            )
            wrote = True
        if p11_snapshot(request) != snapshot:
            raise ValueError("p11-kit sources or metadata changed during regeneration")
        if (expected_sem["hash-files"], expected_sem["hash-links"]) != (
            desired_sem["hash-files"],
            desired_sem["hash-links"],
        ):
            p11_swap_hash(
                stage,
                root,
                workspace,
                json.loads(snapshot)["metadata"],
                expected_hash,
                expected_identity,
            )
            wrote = True
        else:
            p11_check_hash(
                os.path.join(root, "pem/directory-hash"), expected_hash, expected_identity
            )
        for directory in (os.path.join(root, "pem"), os.path.join(stage, "pem")):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        actual_files, actual_links = p11_actual(root)
        if p11_semantics(actual_files, actual_links) != p11_semantics(files, links):
            raise ValueError("p11-kit generated-store verification failed")
        if p11_snapshot(request) != snapshot:
            raise ValueError("p11-kit sources or metadata changed during verification")
    finally:
        WRITE_STARTED = WRITE_STARTED or wrote


def perform(request):
    global WRITE_STARTED
    WRITE_STARTED = False
    if request.get("adapter") != "p11-kit":
        return P11_FILE_PERFORM(request)
    operation = request["operation"]
    if operation not in ("read", "verify", "replace", "reconcile"):
        raise ValueError("Unsupported p11-kit operation")
    root = safe_path(request["p11"]["output_dir"])
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(
                fd,
                (fcntl.LOCK_EX if operation in ("replace", "reconcile") else fcntl.LOCK_SH)
                | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ValueError("p11-kit operation busy; retry after regeneration") from error
        return p11_perform(request, root)
    finally:
        os.close(fd)


def p11_perform(request, root):
    global WRITE_STARTED
    before = p11_snapshot(request)
    operation = request["operation"]
    if operation == "read":
        return {"data": base64.b64encode(before).decode(), "sha256": sha(before)}
    if operation == "verify":
        with tempfile.TemporaryDirectory(prefix="emudhra-p11-verify-") as temporary:
            try:
                _, files, links = p11_stage(request, before, temporary, "expected")
                actual, actual_links = p11_actual(root)
                valid = p11_semantics(actual, actual_links) == p11_semantics(files, links)
                return {
                    "verified": valid,
                    "issues": [] if valid else ["p11-kit outputs differ from configured sources"],
                    "hooks_executed": False,
                    "extra_anchors": p11_extra_anchors(actual, files, root) if not valid else [],
                }
            finally:
                p11_clean(temporary)
    if sha(before) != request["expected_sha256"]:
        raise ValueError("p11-kit source policy, certificates or metadata changed since planning")
    desired = base64.b64decode(request["data"], validate=True) if operation == "replace" else before
    old, new = json.loads(before), json.loads(desired)
    if (
        set(new) != set(old)
        or old["sources"] != new["sources"]
        or old["metadata"] != new["metadata"]
    ):
        raise ValueError("p11-kit adapter only changes its owned policy file")
    if len(desired) > MAX_BYTES:
        raise ValueError("p11-kit replacement snapshot exceeds limit")
    with lock(os.path.join(root, ".emudhra-p11")) as workspace:
        p11_cleanup_pending(root, workspace)
        p11_cleanup_generations(workspace)
        # Staging stays on the target filesystem for the directory exchange.
        with tempfile.TemporaryDirectory(prefix="generation-", dir=workspace) as temporary:
            try:
                stage, files, links = p11_stage(request, desired, temporary, "desired")
                alternate = before
                if operation == "reconcile" and "recovery_from" in request:
                    alternate = base64.b64decode(request["recovery_from"], validate=True)
                    other = json.loads(alternate)
                    if (
                        len(alternate) > MAX_BYTES
                        or set(other) != set(old)
                        or any(other[key] != old[key] for key in ("sources", "metadata"))
                    ):
                        raise ValueError("p11-kit recovery source snapshot conflict")
                if operation == "replace" or alternate != before:
                    _, original_files, original_links = p11_stage(
                        request, alternate, temporary, "original"
                    )
                    removed = p11_denied(original_files) - p11_denied(files)
                    added = p11_denied(files) - p11_denied(original_files)
                    if added and removed:
                        raise ValueError("Mixed p11-kit denial additions/removals are unsupported")
                    if removed:
                        p11_verify_transition(files, original_files, removed)
                    else:
                        p11_verify_transition(original_files, files, added)
                else:
                    original_files, original_links = files, links
                hash_info = os.lstat(os.path.join(root, "pem/directory-hash"))
                expected_identity = (hash_info.st_dev, hash_info.st_ino)
                actual_files, actual_links = p11_actual(root)
                expected_hash = (
                    {
                        name: raw
                        for name, raw in actual_files.items()
                        if name.startswith("pem/directory-hash/")
                    },
                    actual_links,
                )
                actual_sem = p11_semantics(actual_files, actual_links)
                original_sem = p11_semantics(original_files, original_links)
                desired_sem = p11_semantics(files, links)
                if any(
                    actual_sem[key] not in (original_sem[key], desired_sem[key])
                    for key in actual_sem
                ):
                    raise ValueError("p11-kit generated outputs conflict with recovery snapshots")
                actual_hash = (actual_sem["hash-files"], actual_sem["hash-links"])
                if actual_hash not in (
                    (original_sem["hash-files"], original_sem["hash-links"]),
                    (desired_sem["hash-files"], desired_sem["hash-links"]),
                ):
                    raise ValueError("p11-kit hash directory has conflicting edits")
                p11_preflight_files(stage, root, new["metadata"], actual_sem, desired_sem)
                p11_prepare_hash(stage, root, new["metadata"], temporary)
                if p11_snapshot(request) != before:
                    raise ValueError("p11-kit sources changed during staging")
                if operation == "replace":
                    P11_FILE_PERFORM(
                        {
                            "operation": "replace",
                            "path": request["path"],
                            "expected_sha256": sha(base64.b64decode(old["policy"], validate=True)),
                            "data": new["policy"],
                        },
                        allow_empty=True,
                    )
                p11_install(
                    request,
                    stage,
                    files,
                    links,
                    desired,
                    workspace,
                    actual_files,
                    expected_hash,
                    expected_identity,
                )
                return {"sha256": sha(desired)}
            finally:
                p11_clean(temporary)
