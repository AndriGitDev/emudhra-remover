"""Dependency-free Linux helper, sent over SSH. No arbitrary commands or paths from MCP.

The operator must exclusively own the trust directory. The advisory lock serializes
our writers; package managers do not honor it, so hashes are checked again before rename.
"""

import base64
import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
import tempfile
from contextlib import contextmanager

MAX_BYTES = 16 * 1024 * 1024
WRITE_STARTED = False


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise ValueError("Symlinked or noncanonical trust paths are unsupported")
    return path


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Trust store must be a regular file with one link")
        data = file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Trust store exceeds 16 MiB")
    return data, info


@contextmanager
def lock(path):
    workspace = path + ".emudhra-work"
    try:
        os.mkdir(workspace, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(workspace)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("Unsafe target workspace")
    fd = os.open(workspace + "/lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError("Unsafe lock file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # A crash can leave temporary bytes, but never a regular certificate file
        # directly in the trust directory. Only our private workspace is cleaned.
        for name in os.listdir(workspace):
            if name.startswith("pending-"):
                candidate = os.path.join(workspace, name)
                pending_info = os.lstat(candidate)
                if stat.S_ISREG(pending_info.st_mode) and pending_info.st_uid == os.geteuid():
                    os.unlink(candidate)
                else:
                    raise ValueError("Unsafe stale workspace entry")
        yield workspace
    finally:
        os.close(fd)


def xattrs(path):
    try:
        return {key: os.getxattr(path, key) for key in os.listxattr(path)}
    except OSError as error:
        if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return {}
        raise


def perform(request, *, allow_empty=False):
    global WRITE_STARTED
    WRITE_STARTED = False
    path = safe_path(request["path"])
    if request["operation"] == "read":
        data, _ = read(path)
        return {"data": base64.b64encode(data).decode(), "sha256": sha(data)}
    if request["operation"] != "replace":
        raise ValueError("Unsupported operation")
    data = base64.b64decode(request["data"], validate=True)
    if (not data and not allow_empty) or len(data) > MAX_BYTES:
        raise ValueError("Invalid replacement size")
    with lock(path) as workspace:
        original, info = read(path)
        if sha(original) != request["expected_sha256"]:
            raise ValueError("Trust store changed since planning; rescan before retrying")
        # Atomic rename cannot safely preserve ACLs/SELinux labels implicitly.
        # Preserve all xattrs explicitly, or fail before replacing the original.
        attrs = xattrs(path)
        fd, temporary = tempfile.mkstemp(prefix="pending-", dir=workspace)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                temporary_info = os.fstat(file.fileno())
                if (info.st_uid, info.st_gid) != (temporary_info.st_uid, temporary_info.st_gid):
                    os.fchown(file.fileno(), info.st_uid, info.st_gid)
                for key in xattrs(file.fileno()).keys() - attrs.keys():
                    os.removexattr(file.fileno(), key)
                for key, value in attrs.items():
                    os.setxattr(file.fileno(), key, value)
                os.fchmod(file.fileno(), stat.S_IMODE(info.st_mode))
                final_info = os.fstat(file.fileno())
                if (final_info.st_uid, final_info.st_gid, stat.S_IMODE(final_info.st_mode)) != (
                    info.st_uid,
                    info.st_gid,
                    stat.S_IMODE(info.st_mode),
                ) or xattrs(file.fileno()) != attrs:
                    raise ValueError("Cannot preserve trust-store metadata exactly")
                os.fsync(file.fileno())
            current, current_info = read(path)
            if sha(current) != sha(original) or current_info.st_ino != info.st_ino:
                raise ValueError("Concurrent trust-store update detected")
            WRITE_STARTED = True
            os.replace(temporary, path)
            directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        verified, _ = read(path)
        if verified != data:
            raise ValueError("Post-write verification failed; inspect plan before recovery")
        return {"sha256": sha(verified)}


def main():
    try:
        # Recovery may carry two bounded snapshots (original and modified).
        request = json.loads(sys.stdin.buffer.read(48 * 1024 * 1024 + 1))
        print(json.dumps(perform(request)))
    except Exception as error:
        print(json.dumps({"error": str(error), "write_may_have_occurred": WRITE_STARTED}))
        sys.exit(1)


if __name__ == "__main__":
    main()
