"""
3DES file encryption engine (Encrypt-then-MAC).

Blob layout (all produced client-side, before anything touches the cloud):

    magic "3DSC" (4) | version (1) | IV (8) | ciphertext (n*8) | HMAC-SHA256 tag (32)

* Cipher : Triple DES (3-key EDE, 168-bit nominal key) in CBC mode, PKCS#7 padding.
* Integrity: HMAC-SHA256 over (len(aad) | aad | header | ciphertext), verified
  BEFORE any decryption happens. The AAD is the file id, which binds a blob to
  its metadata record and defeats blob-swapping attacks by the storage provider.
* Keys   : a fresh random 3DES key + a fresh random MAC key for every file
  (see FileKey). Per-file keys also keep us far below the ~2^32-block "Sweet32"
  birthday bound of 64-bit block ciphers.
* Streaming: files are processed in 1 MiB chunks, so memory use is constant.
"""

import hmac as _hmac
import os
from dataclasses import dataclass

from Crypto.Cipher import DES3
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MAGIC = b"3DSC"
VERSION = 1
BLOCK = DES3.block_size  # 8 bytes
IV_LEN = BLOCK
TAG_LEN = 32
HEADER_LEN = len(MAGIC) + 1 + IV_LEN
CHUNK = 1024 * 1024  # multiple of the block size
MAX_FILE_BYTES = 1 << 30  # 1 GiB cap per key (Sweet32 mitigation)
MIN_BLOB = HEADER_LEN + BLOCK + TAG_LEN


class IntegrityError(Exception):
    """Blob failed authentication (tampered, truncated, wrong key or wrong file)."""


class FileTooLarge(Exception):
    pass


@dataclass(frozen=True)
class FileKey:
    des_key: bytes  # 24 bytes, three independent 8-byte DES keys, parity-adjusted
    mac_key: bytes  # 32 bytes

    def to_bytes(self) -> bytes:
        return self.des_key + self.mac_key

    @staticmethod
    def from_bytes(b: bytes) -> "FileKey":
        if len(b) != 56:
            raise ValueError("bad key bundle length")
        return FileKey(b[:24], b[24:])


def generate_file_key() -> FileKey:
    """Random 3-key 3DES key. PyCryptodome rejects degenerate keys (K1==K2 etc.), so retry."""
    while True:
        k = DES3.adjust_key_parity(get_random_bytes(24))
        try:
            DES3.new(k, DES3.MODE_ECB)
        except ValueError:
            continue
        return FileKey(k, get_random_bytes(32))


def _mac_start(fk: FileKey, aad: bytes, header: bytes):
    mac = HMAC.new(fk.mac_key, digestmod=SHA256)
    mac.update(len(aad).to_bytes(2, "big") + aad + header)
    return mac


def encrypt_file(src: str, dst: str, fk: FileKey, aad: bytes = b"") -> int:
    """Encrypt src -> dst. Returns size of the produced blob in bytes."""
    if os.path.getsize(src) > MAX_FILE_BYTES:
        raise FileTooLarge(
            f"file exceeds {MAX_FILE_BYTES} bytes (3DES 64-bit block limit)"
        )
    iv = get_random_bytes(IV_LEN)
    header = MAGIC + bytes([VERSION]) + iv
    mac = _mac_start(fk, aad, header)
    cipher = DES3.new(fk.des_key, DES3.MODE_CBC, iv)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(header)
        chunk = fi.read(CHUNK)
        while True:
            nxt = fi.read(CHUNK)
            if not nxt:  # last chunk -> pad
                ct = cipher.encrypt(pad(chunk, BLOCK))
                fo.write(ct)
                mac.update(ct)
                break
            ct = cipher.encrypt(chunk)
            fo.write(ct)
            mac.update(ct)
            chunk = nxt
        fo.write(mac.digest())
    return os.path.getsize(dst)


def verify_blob(path: str, fk: FileKey, aad: bytes = b"") -> bytes:
    """Authenticate a blob (streaming). Returns the IV. Raises IntegrityError."""
    size = os.path.getsize(path)
    if size < MIN_BLOB or (size - HEADER_LEN - TAG_LEN) % BLOCK != 0:
        raise IntegrityError("malformed blob")
    with open(path, "rb") as f:
        header = f.read(HEADER_LEN)
        if header[:4] != MAGIC or header[4] != VERSION:
            raise IntegrityError("bad magic/version")
        mac = _mac_start(fk, aad, header)
        remaining = size - HEADER_LEN - TAG_LEN
        while remaining:
            data = f.read(min(CHUNK, remaining))
            mac.update(data)
            remaining -= len(data)
        tag = f.read(TAG_LEN)
    if not _hmac.compare_digest(mac.digest(), tag):
        raise IntegrityError("authentication tag mismatch")
    return header[5:]


def decrypt_file(src: str, dst: str, fk: FileKey, aad: bytes = b"") -> int:
    """Verify-then-decrypt src -> dst. dst is only written after authentication succeeds."""
    iv = verify_blob(src, fk, aad)
    cipher = DES3.new(fk.des_key, DES3.MODE_CBC, iv)
    ct_len = os.path.getsize(src) - HEADER_LEN - TAG_LEN
    written = 0
    try:
        with open(src, "rb") as fi, open(dst, "wb") as fo:
            fi.seek(HEADER_LEN)
            remaining = ct_len
            while remaining:
                data = fi.read(min(CHUNK, remaining))
                remaining -= len(data)
                pt = cipher.decrypt(data)
                if remaining == 0:
                    try:
                        pt = unpad(pt, BLOCK)
                    except ValueError as e:
                        raise IntegrityError("bad padding") from e
                fo.write(pt)
                written += len(pt)
    except Exception:
        if os.path.exists(dst):
            os.remove(dst)
        raise
    return written
