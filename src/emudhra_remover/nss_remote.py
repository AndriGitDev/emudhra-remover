# ruff: noqa: F821
# Appended to remote.py in the fixed helper namespace.
"""Snapshot a closed NSS SQL pair; recover either interrupted database replacement."""

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


@contextmanager
def nss_directory_locked(path, writing):
    descriptor = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        mode = fcntl.LOCK_EX if writing else fcntl.LOCK_SH
        try:
            fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("NSS operation busy; retry when it completes") from error
        yield
    finally:
        os.close(descriptor)


def nss_validate_replacement(decoded):
    # Reject malformed or key-bearing candidates before replacing either member.
    # A valid companion is also necessary for interrupted-pair recovery reads.
    with tempfile.TemporaryDirectory(prefix="emudhra-nss-preflight-") as temporary:
        for member, table in (("cert9", "nssPublic"), ("key4", "nssPrivate")):
            candidate = os.path.join(temporary, member + ".db")
            with open(candidate, "wb") as file:
                file.write(decoded[member])
            db = sqlite3.connect(
                "file:" + quote(candidate, safe="/") + "?mode=ro&immutable=1", uri=True
            )
            try:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("NSS replacement database integrity check failed")
                count = db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                if member == "key4" and count:
                    raise ValueError("NSS replacement contains private-key records")
            finally:
                db.close()


def perform(request):
    global WRITE_STARTED
    WRITE_STARTED = False
    if request.get("adapter") != "nss-sql":
        return NSS_FILE_PERFORM(request)
    path = safe_path(request["path"])
    operation = request["operation"]
    if operation not in ("read", "replace"):
        raise ValueError("Unsupported NSS operation")
    writing = operation == "replace"
    with nss_directory_locked(path, writing), nss_locked(path, writing):
        before = nss_snapshot(path)
        if operation == "read":
            return {"data": base64.b64encode(before).decode(), "sha256": sha(before)}
        replacement = base64.b64decode(request["data"], validate=True)
        old, new = json.loads(before), json.loads(replacement)
        if set(new) != {"key4", "cert9"} or len(replacement) > MAX_BYTES:
            raise ValueError("Invalid NSS database pair")
        if "recovery_from" in request:
            expected = base64.b64decode(request["recovery_from"], validate=True)
            if sha(expected) != request["expected_sha256"]:
                raise ValueError("NSS recovery snapshot hash mismatch")
            expected = json.loads(expected)
            if set(expected) != set(new) or any(old[k] not in (expected[k], new[k]) for k in new):
                raise ValueError("NSS database pair conflicts with recovery snapshots")
        elif sha(before) != request["expected_sha256"]:
            raise ValueError("NSS database pair changed since planning")
        # Every member must be complete and bounded before any replacement starts.
        decoded = {key: base64.b64decode(value, validate=True) for key, value in new.items()}
        if any(not data or len(data) > MAX_BYTES for data in decoded.values()):
            raise ValueError("Invalid NSS database size")
        nss_validate_replacement(decoded)
        nss_guard(path)
        wrote = False
        try:
            for member, filename in (("cert9", "cert9.db"), ("key4", "key4.db")):
                if old[member] == new[member]:
                    continue
                NSS_FILE_PERFORM(
                    {
                        "operation": "replace",
                        "path": os.path.join(os.path.dirname(path), filename),
                        "expected_sha256": sha(base64.b64decode(old[member], validate=True)),
                        "data": new[member],
                    }
                )
                wrote = True
            if nss_snapshot(path) != replacement:
                raise ValueError("NSS post-write pair verification failed")
        finally:
            # The base writer resets WRITE_STARTED on entry. A pre-write failure
            # on the second file must not hide a successful first replacement.
            WRITE_STARTED = WRITE_STARTED or wrote
        return {"sha256": sha(replacement)}
