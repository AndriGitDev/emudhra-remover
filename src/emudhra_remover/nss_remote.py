# ruff: noqa: F821
# Appended to remote.py in the fixed helper namespace.
"""Snapshot a closed, trust-only NSS SQL pair; write only cert9.db."""

import sqlite3
import struct
from urllib.parse import quote

NSS_FILE_PERFORM = perform


def nss_guard(path):
    if os.path.basename(path) != "cert9.db":
        raise ValueError("NSS adapter requires the unprefixed cert9.db path")
    directory = os.path.dirname(path)
    for marker in (".parentlock", "parent.lock", "lock"):
        if os.path.lexists(os.path.join(directory, marker)):
            raise ValueError(
                "NSS profile lock exists; close the application and resolve stale locks"
            )
    for name in ("cert9.db", "key4.db"):
        dbpath = safe_path(os.path.join(directory, name))
        for suffix in ("-wal", "-shm", "-journal"):
            if os.path.lexists(dbpath + suffix):
                raise ValueError(
                    "NSS SQLite sidecars exist; close/checkpoint the application first"
                )


@contextmanager
def nss_locked(path, writing):
    nss_guard(path)
    descriptors = []
    try:
        for name in ("cert9.db", "key4.db"):
            dbpath = os.path.join(os.path.dirname(path), name)
            descriptor = os.open(
                dbpath, (os.O_RDWR if writing else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            descriptors.append(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("NSS database must be a regular file with one link")
            if not hasattr(fcntl, "F_OFD_SETLK") or struct.calcsize("P") != 8:
                raise ValueError("NSS adapter requires 64-bit Linux OFD locks")
            mode = fcntl.F_WRLCK if writing else fcntl.F_RDLCK
            # OFD locks conflict with SQLite POSIX locks but survive other file
            # descriptor closes in this process (ordinary lockf locks do not).
            flock = struct.pack("hhqqi4x", mode, os.SEEK_SET, 0x40000000, 512, 0)
            fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, flock)
        nss_guard(path)
        yield
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def nss_snapshot(path):
    nss_guard(path)
    keypath = os.path.join(os.path.dirname(path), "key4.db")
    connection = sqlite3.connect(
        "file:" + quote(keypath, safe="/") + "?mode=ro&immutable=1", uri=True
    )
    try:
        if connection.execute("SELECT COUNT(*) FROM nssPrivate").fetchone()[0]:
            raise ValueError("NSS adapter refuses databases containing private-key records")
    finally:
        connection.close()
    cert, _ = read(path)
    key, _ = read(keypath)
    nss_guard(path)
    data = json.dumps(
        {"cert9": base64.b64encode(cert).decode(), "key4": base64.b64encode(key).decode()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(data) > MAX_BYTES:
        raise ValueError("NSS snapshot exceeds size limit")
    return data


def perform(request):
    global WRITE_STARTED
    WRITE_STARTED = False
    if request.get("adapter") != "nss-sql":
        return NSS_FILE_PERFORM(request)
    path = safe_path(request["path"])
    operation = request["operation"]
    if operation not in ("read", "replace"):
        raise ValueError("Unsupported NSS operation")
    with nss_locked(path, operation == "replace"):
        before = nss_snapshot(path)
        if operation == "read":
            return {"data": base64.b64encode(before).decode(), "sha256": sha(before)}
        if sha(before) != request["expected_sha256"]:
            raise ValueError("NSS database pair changed since planning")
        replacement = base64.b64decode(request["data"], validate=True)
        old, new = json.loads(before), json.loads(replacement)
        if old["key4"] != new["key4"] or set(new) != {"key4", "cert9"}:
            raise ValueError("NSS companion key database must remain unchanged")
        nss_guard(path)
        NSS_FILE_PERFORM(
            {
                "operation": "replace",
                "path": path,
                "expected_sha256": sha(base64.b64decode(old["cert9"])),
                "data": new["cert9"],
            }
        )
        if nss_snapshot(path) != replacement:
            raise ValueError("NSS post-write pair verification failed")
        return {"sha256": sha(replacement)}
