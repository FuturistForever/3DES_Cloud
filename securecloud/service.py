"""
Core service: registration, authentication, encrypted upload/download, sharing, revocation.

Key hierarchy
-------------
password --scrypt--> auth hash (stored)                      [login check]
password --scrypt+AES--> protects the user's RSA-2048 private key (stored encrypted)
per-file random 3DES key + MAC key  --RSA-OAEP(pubkey of each authorized user)--> access.wrapped_key

The server/cloud never holds a usable file key or a password: a file can only be
decrypted by someone who can unlock an RSA private key listed in the access table.
"""

import hmac
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA

from .cloud_backend import CloudBackend
from .crypto_engine import (
    FileKey,
    IntegrityError,
    decrypt_file,
    encrypt_file,
    generate_file_key,
)
from .database import Database

SCRYPT_N = 2**14
MAX_FAILED = 5
LOCK_SECONDS = 300
GENERIC_DENY = (
    "file not found or access denied"  # identical message: no existence oracle
)


class AuthError(Exception): ...


class AccountLocked(AuthError): ...


class AccessDenied(Exception): ...


@dataclass
class Session:
    username: str
    private_key: RSA.RsaKey


def _oaep(key):
    return PKCS1_OAEP.new(key, hashAlgo=SHA256)


class SecureCloudService:
    def __init__(
        self,
        data_dir: str,
        cloud: CloudBackend,
        max_failed=MAX_FAILED,
        lock_seconds=LOCK_SECONDS,
    ):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.db = Database(os.path.join(data_dir, "metadata.db"))
        self.cloud = cloud
        self.max_failed = max_failed
        self.lock_seconds = lock_seconds

    # ------------------------------------------------------------------ audit
    def _audit(self, user, action, target, outcome):
        with self.db.conn() as c:
            c.execute(
                "INSERT INTO audit(ts,username,action,target,outcome) VALUES(?,?,?,?,?)",
                (time.time(), user, action, target, outcome),
            )

    def audit_log(self, limit=50):
        with self.db.conn() as c:
            return [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
                )
            ]

    # ------------------------------------------------------------------ users
    def register(self, username: str, password: str) -> None:
        if not username.isalnum() or len(password) < 8:
            raise ValueError("username must be alphanumeric; password >= 8 chars")
        key = RSA.generate(2048)
        salt = os.urandom(16)
        pw_hash = scrypt(password.encode(), salt, 32, N=SCRYPT_N, r=8, p=1)
        enc_priv = key.export_key(
            passphrase=password, pkcs=8, protection="scryptAndAES128-CBC"
        )
        with self.db.conn() as c:
            if c.execute(
                "SELECT 1 FROM users WHERE username=?", (username,)
            ).fetchone():
                raise ValueError("username taken")
            c.execute(
                "INSERT INTO users VALUES(?,?,?,?,?,0,0,?)",
                (
                    username,
                    salt,
                    pw_hash,
                    key.publickey().export_key(),
                    enc_priv,
                    time.time(),
                ),
            )
        self._audit(username, "register", None, "ok")

    def login(self, username: str, password: str) -> Session:
        outcome, row = None, None
        with self.db.conn() as c:
            row = c.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            now = time.time()
            if row is None:  # equalize timing, hide user existence
                scrypt(password.encode(), b"0" * 16, 32, N=SCRYPT_N, r=8, p=1)
                outcome = "unknown-user"
            elif row["locked_until"] > now:
                outcome = "locked"
            else:
                h = scrypt(password.encode(), row["pw_salt"], 32, N=SCRYPT_N, r=8, p=1)
                if hmac.compare_digest(h, row["pw_hash"]):
                    c.execute(
                        "UPDATE users SET failed_attempts=0 WHERE username=?",
                        (username,),
                    )
                    outcome = "ok"
                else:
                    failed = row["failed_attempts"] + 1
                    locked = now + self.lock_seconds if failed >= self.max_failed else 0
                    c.execute(
                        "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                        (0 if locked else failed, locked, username),
                    )
                    outcome = "bad-password"
        self._audit(username, "login", None, outcome)  # after the connection is closed
        if outcome == "locked":
            raise AccountLocked("account temporarily locked")
        if outcome != "ok":
            raise AuthError("invalid credentials")
        return Session(
            username, RSA.import_key(row["enc_private_key"], passphrase=password)
        )

    def _pubkey(self, username):
        with self.db.conn() as c:
            r = c.execute(
                "SELECT public_key FROM users WHERE username=?", (username,)
            ).fetchone()
        return RSA.import_key(r["public_key"]) if r else None

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _blob(file_id):
        return f"{file_id}.enc"

    def _file_key(self, s: Session, file_id: str) -> FileKey:
        with self.db.conn() as c:
            r = c.execute(
                "SELECT wrapped_key FROM access WHERE file_id=? AND username=?",
                (file_id, s.username),
            ).fetchone()
        if r is None:
            self._audit(s.username, "access", file_id, "denied")
            raise AccessDenied(GENERIC_DENY)
        try:
            return FileKey.from_bytes(_oaep(s.private_key).decrypt(r["wrapped_key"]))
        except ValueError as e:
            raise IntegrityError("cannot unwrap file key") from e

    def _owner_check(self, s: Session, file_id: str):
        with self.db.conn() as c:
            r = c.execute(
                "SELECT owner FROM files WHERE file_id=?", (file_id,)
            ).fetchone()
        if r is None or r["owner"] != s.username:
            self._audit(s.username, "owner-op", file_id, "denied")
            raise AccessDenied(GENERIC_DENY)

    # ------------------------------------------------------------------ file ops
    def upload(self, s: Session, path: str, name: str | None = None) -> dict:
        file_id = uuid.uuid4().hex
        fk = generate_file_key()
        plain_size = os.path.getsize(path)
        with tempfile.TemporaryDirectory() as td:
            blob = os.path.join(td, "blob")
            t0 = time.perf_counter()
            cloud_size = encrypt_file(path, blob, fk, aad=file_id.encode())
            t1 = time.perf_counter()
            self.cloud.put(self._blob(file_id), blob)
            t2 = time.perf_counter()
        wrapped = _oaep(s.private_key.publickey()).encrypt(fk.to_bytes())
        with self.db.conn() as c:
            c.execute(
                "INSERT INTO files VALUES(?,?,?,?,?,?)",
                (
                    file_id,
                    s.username,
                    name or os.path.basename(path),
                    plain_size,
                    cloud_size,
                    time.time(),
                ),
            )
            c.execute(
                "INSERT INTO access VALUES(?,?,?)", (file_id, s.username, wrapped)
            )
        self._audit(s.username, "upload", file_id, "ok")
        return dict(
            file_id=file_id,
            plain_size=plain_size,
            cloud_size=cloud_size,
            encrypt_s=t1 - t0,
            upload_s=t2 - t1,
        )

    def download(self, s: Session, file_id: str, dest: str) -> dict:
        fk = self._file_key(s, file_id)
        part = dest + ".part"
        with tempfile.TemporaryDirectory() as td:
            blob = os.path.join(td, "blob")
            t0 = time.perf_counter()
            try:
                self.cloud.get(self._blob(file_id), blob)
            except FileNotFoundError:
                raise AccessDenied(GENERIC_DENY)
            t1 = time.perf_counter()
            try:
                decrypt_file(blob, part, fk, aad=file_id.encode())
            except IntegrityError:
                self._audit(s.username, "download", file_id, "INTEGRITY-FAILURE")
                raise
            t2 = time.perf_counter()
        os.replace(part, dest)
        self._audit(s.username, "download", file_id, "ok")
        return dict(
            download_s=t1 - t0, decrypt_s=t2 - t1, plain_size=os.path.getsize(dest)
        )

    def share(self, s: Session, file_id: str, target_user: str) -> None:
        self._owner_check(s, file_id)
        pub = self._pubkey(target_user)
        if pub is None:
            raise ValueError("no such user")
        fk = self._file_key(s, file_id)
        wrapped = _oaep(pub).encrypt(fk.to_bytes())
        with self.db.conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO access VALUES(?,?,?)",
                (file_id, target_user, wrapped),
            )
        self._audit(s.username, "share", f"{file_id}->{target_user}", "ok")

    def revoke(self, s: Session, file_id: str, target_user: str) -> None:
        """Remove access AND rotate the file key, so the revoked user's old copy of the
        key is useless against the (re-encrypted) cloud blob."""
        self._owner_check(s, file_id)
        if target_user == s.username:
            raise ValueError("owner cannot revoke self")
        old_fk = self._file_key(s, file_id)
        with self.db.conn() as c:
            c.execute(
                "DELETE FROM access WHERE file_id=? AND username=?",
                (file_id, target_user),
            )
            remaining = [
                r["username"]
                for r in c.execute(
                    "SELECT username FROM access WHERE file_id=?", (file_id,)
                )
            ]
        new_fk = generate_file_key()
        aad = file_id.encode()
        with tempfile.TemporaryDirectory() as td:
            blob, plain, blob2 = (os.path.join(td, n) for n in ("b", "p", "b2"))
            self.cloud.get(self._blob(file_id), blob)
            decrypt_file(blob, plain, old_fk, aad)
            size = encrypt_file(plain, blob2, new_fk, aad)
            os.remove(plain)
            self.cloud.put(self._blob(file_id), blob2)
        with self.db.conn() as c:
            for u in remaining:
                w = _oaep(self._pubkey(u)).encrypt(new_fk.to_bytes())
                c.execute(
                    "UPDATE access SET wrapped_key=? WHERE file_id=? AND username=?",
                    (w, file_id, u),
                )
            c.execute("UPDATE files SET cloud_size=? WHERE file_id=?", (size, file_id))
        self._audit(s.username, "revoke", f"{file_id}->{target_user}", "ok+key-rotated")

    def delete(self, s: Session, file_id: str) -> None:
        self._owner_check(s, file_id)
        self.cloud.delete(self._blob(file_id))
        with self.db.conn() as c:
            c.execute("DELETE FROM files WHERE file_id=?", (file_id,))
        self._audit(s.username, "delete", file_id, "ok")

    def list_files(self, s: Session) -> list[dict]:
        with self.db.conn() as c:
            rows = c.execute(
                """SELECT f.file_id, f.name, f.owner, f.plain_size, f.cloud_size
                                FROM files f JOIN access a ON a.file_id=f.file_id
                                WHERE a.username=? ORDER BY f.created""",
                (s.username,),
            ).fetchall()
        return [dict(r) for r in rows]
