# ruff: noqa: F821
# Executed after remote.py in one isolated helper namespace.
"""Appended to the fixed Linux helper; uses only its primitives and the stdlib."""

import re
import subprocess

FILE_PERFORM = perform


def debian_encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def debian_entries(config):
    entries = []
    if any(byte != 10 and not 32 <= byte <= 126 for byte in config):
        raise ValueError("Debian configuration must use ASCII text and LF line endings")
    for line in config.decode("ascii").split("\n"):
        if not line or line.startswith("#"):
            continue
        name = line.removeprefix("!")
        if (
            not re.fullmatch(r"[A-Za-z0-9_./+-]+\.crt", name)
            or name.startswith("/")
            or any(p in ("", ".", "..") for p in name.split("/"))
        ):
            raise ValueError("Unsupported or unsafe Debian configuration entry")
        entries.append((name, not line.startswith("!")))
    if len({name for name, _ in entries}) != len(entries):
        raise ValueError("Duplicate Debian configuration entries")
    return entries


def debian_snapshot(request):
    config, _ = read(safe_path(request["path"]))
    options = request["debian"]
    for directory in (options["certs_dir"], options["local_certs_dir"], options["output_dir"]):
        safe_path(directory)
        if not os.path.isdir(directory):
            raise ValueError("Debian source/output directories must already exist")
    entries = debian_entries(config)
    if len(entries) > 4096:
        raise ValueError("Too many source certificates")
    total = len(config)
    sources = {}
    for name, active in entries:
        try:
            data, _ = read(safe_path(os.path.join(options["certs_dir"], name)))
        except FileNotFoundError:
            if active:
                raise
            sources[name] = None
            continue
        total += len(data) * 2
        if total > MAX_BYTES:
            raise ValueError("Debian snapshot exceeds size limit")
        sources[name] = base64.b64encode(data).decode()
    local = {}
    for root, directories, names in os.walk(options["local_certs_dir"]):
        for name in directories:
            safe_path(os.path.join(root, name))
        for name in names:
            if name.endswith(".crt"):
                path = safe_path(os.path.join(root, name))
                data, _ = read(path)
                total += len(data) * 2
                if total > MAX_BYTES:
                    raise ValueError("Debian snapshot exceeds size limit")
                local[os.path.relpath(path, options["local_certs_dir"])] = base64.b64encode(
                    data
                ).decode()
        if len(sources) + len(local) > 4096:
            raise ValueError("Too many source certificates")
    result = debian_encode(
        {"config": base64.b64encode(config).decode(), "sources": sources, "local": local}
    )
    if len(result) > MAX_BYTES:
        raise ValueError("Debian snapshot exceeds size limit")
    return result


def debian_fingerprints(data):
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", data, re.S)
    remainder = re.sub(
        rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", b"", data, flags=re.S
    )
    if b"-----BEGIN" in remainder or b"-----END" in remainder:
        raise ValueError("Malformed generated certificate bundle")
    result = []
    for block in blocks:
        body = block.replace(b"-----BEGIN CERTIFICATE-----", b"").replace(
            b"-----END CERTIFICATE-----", b""
        )
        der = base64.b64decode(re.sub(rb"\s", b"", body), validate=True)
        result.append(sha(der))
    return result


def debian_verify(request, snapshot):
    value = json.loads(snapshot)
    expected = []
    for name, active in debian_entries(base64.b64decode(value["config"])):
        if active:
            expected.extend(debian_fingerprints(base64.b64decode(value["sources"][name])))
    for data in value["local"].values():
        expected.extend(debian_fingerprints(base64.b64decode(data)))
    directory = request["debian"]["output_dir"]
    bundle, _ = read(safe_path(os.path.join(directory, "ca-certificates.crt")))
    issues, extras = [], []
    if sorted(debian_fingerprints(bundle)) != sorted(expected):
        issues.append("Generated Debian bundle does not match configured sources")
    managed = {
        os.path.join(request["debian"]["certs_dir"], name)
        for name, active in debian_entries(base64.b64decode(value["config"]))
        if active
    }
    managed.update(
        os.path.join(request["debian"]["local_certs_dir"], name) for name in value["local"]
    )
    managed.add(os.path.join(directory, "ca-certificates.crt"))
    observed = []
    for name in sorted(os.listdir(directory)):
        if name in ("ca-certificates.crt", "ca-certificates.crt.new"):
            continue
        if not (
            name.endswith((".pem", ".crt", ".cer")) or re.fullmatch(r"[0-9a-f]{8}\.[0-9]+", name)
        ):
            continue
        path = os.path.realpath(os.path.join(directory, name))
        if os.path.isdir(path):
            continue
        data, _ = read(safe_path(path))
        fingerprints = debian_fingerprints(data)
        observed.extend(fingerprints)
        if path not in managed:
            issues.append("Unmanaged CApath entry: " + name)
            extras.extend({"source": name, "sha256": fingerprint} for fingerprint in fingerprints)
    if set(observed) != set(expected):
        issues.append("Generated Debian CApath entries do not match configured sources")
    return {
        "verified": not issues,
        "issues": issues,
        "extra_anchors": extras,
        "certificates": len(expected),
        "hooks_executed": False,
    }


def debian_regenerate(request, workspace):
    global WRITE_STARTED
    empty_hooks = os.path.join(workspace, "empty-hooks")
    os.makedirs(empty_hooks, mode=0o700, exist_ok=True)
    if os.listdir(empty_hooks) or os.path.islink(empty_hooks):
        raise ValueError("Unsafe empty hooks directory")
    options = request["debian"]
    WRITE_STARTED = True
    subprocess.run(
        [
            "/usr/sbin/update-ca-certificates",
            "--fresh",
            "--certsconf",
            request["path"],
            "--certsdir",
            options["certs_dir"],
            "--localcertsdir",
            options["local_certs_dir"],
            "--etccertsdir",
            options["output_dir"],
            "--hooksdir",
            empty_hooks,
        ],
        check=True,
        timeout=90,
        capture_output=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )


def perform(request):
    global WRITE_STARTED
    WRITE_STARTED = False
    if request.get("adapter") != "debian":
        return FILE_PERFORM(request)
    operation = request["operation"]
    if operation == "read":
        data = debian_snapshot(request)
        return {"data": base64.b64encode(data).decode(), "sha256": sha(data)}
    if operation == "verify":
        return debian_verify(request, debian_snapshot(request))
    if operation not in ("replace", "reconcile"):
        raise ValueError("Unsupported Debian operation")
    path = safe_path(request["path"])
    with lock(path + ".debian-operation") as workspace:
        before = debian_snapshot(request)
        if sha(before) != request["expected_sha256"]:
            raise ValueError("Debian configuration or source certificates changed since planning")
        if operation == "replace":
            desired = base64.b64decode(request["data"], validate=True)
            old, new = json.loads(before), json.loads(desired)
            if old["sources"] != new["sources"] or old["local"] != new["local"]:
                raise ValueError("Debian adapter only changes configuration selections")
            config = base64.b64decode(new["config"], validate=True)
            debian_entries(config)
            FILE_PERFORM(
                {
                    "operation": "replace",
                    "path": path,
                    "expected_sha256": sha(base64.b64decode(old["config"])),
                    "data": new["config"],
                }
            )
        else:
            desired = before
        debian_regenerate(request, workspace)
        after = debian_snapshot(request)
        if after != desired:
            raise ValueError("Source/configuration changed during Debian regeneration")
        verification = debian_verify(request, after)
        if not verification["verified"]:
            raise ValueError("; ".join(verification["issues"]))
        return {"sha256": sha(after)}
