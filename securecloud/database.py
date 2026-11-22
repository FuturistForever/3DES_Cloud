"""SQLite metadata store (users, file records, per-user wrapped keys, audit log)."""

import contextlib
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    pw_salt BLOB NOT NULL,
    pw_hash BLOB NOT NULL,
    public_key BLOB NOT NULL,
    enc_private_key BLOB NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS files(
    file_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL REFERENCES users(username),
    name TEXT NOT NULL,
    plain_size INTEGER NOT NULL,
    cloud_size INTEGER NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS access(
    file_id TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES users(username),
    wrapped_key BLOB NOT NULL,
    PRIMARY KEY(file_id, username)
);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextlib.contextmanager
    def conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()
