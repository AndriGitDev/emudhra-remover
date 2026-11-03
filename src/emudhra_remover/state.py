"""Private durable plan journal. Backups are committed before any target write."""

import fcntl
import json
import os
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class State:
    def __init__(self, directory: Path):
        directory = directory.absolute()
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or directory.resolve() != directory
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError(
                "State directory must be owned by this user, mode 0700, without symlinks"
            )
        # One server per journal prevents cross-process apply/rollback races. The
        # lock is released by the OS on crash, making interrupted plans recoverable.
        self.lock_fd = os.open(
            directory / "server.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            lock_info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
                raise ValueError("Unsafe journal lock")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise
        self.path = directory / "plans.sqlite3"
        # Reject links and overly permissive state left by another process.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError("Unsafe journal file")
        finally:
            os.close(fd)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS plans (
                id TEXT PRIMARY KEY, created REAL NOT NULL, target TEXT NOT NULL,
                before BLOB NOT NULL, after BLOB NOT NULL, report TEXT NOT NULL,
                status TEXT NOT NULL, error TEXT
            )""")

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def __del__(self):
        if getattr(self, "lock_fd", None) is not None:
            self.close()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, target: dict, before: bytes, after: bytes, report: dict) -> str:
        plan_id = uuid.uuid4().hex
        with self.connect() as db:
            db.execute(
                "INSERT INTO plans VALUES (?, ?, ?, ?, ?, ?, 'planned', NULL)",
                (plan_id, time.time(), json.dumps(target), before, after, json.dumps(report)),
            )
        return plan_id

    def get(self, plan_id: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown plan ID")
        return dict(row)

    def claim(self, plan_id: str, status: str, expected: tuple[str, ...]):
        with self.connect() as db:
            placeholders = ",".join("?" for _ in expected)
            changed = db.execute(
                f"UPDATE plans SET status=?, error=NULL WHERE id=? AND status IN ({placeholders})",
                (status, plan_id, *expected),
            ).rowcount
        if changed != 1:
            raise ValueError("Plan is already running or is in an incompatible state")

    def finish(self, plan_id: str, status: str, error: str | None = None):
        with self.connect() as db:
            db.execute("UPDATE plans SET status=?, error=? WHERE id=?", (status, error, plan_id))
