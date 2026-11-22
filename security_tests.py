#!/usr/bin/env python3
"""
Security verification suite.  Run:  python security_tests.py -v

A. Unauthorized access   B. File tampering   C. Brute force   D. Data leakage
"""

import os
import shutil
import tempfile
import unittest

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

from securecloud import (
    AccessDenied,
    AccountLocked,
    AuthError,
    IntegrityError,
    LocalCloudBackend,
    SecureCloudService,
)
from securecloud.crypto_engine import (
    CHUNK,
    FileKey,
    decrypt_file,
    encrypt_file,
    generate_file_key,
)

SECRET = b"TOP-SECRET-PAYROLL-2026 " * 50

# RSA-2048 keygen is slow; pre-generate a small pool once so the suite runs in seconds.
import itertools
from Crypto.PublicKey import RSA
import securecloud.service as _svc_mod

_POOL = itertools.cycle([RSA.generate(2048) for _ in range(3)])


class _FastRSA:
    generate = staticmethod(lambda bits: next(_POOL))
    import_key = staticmethod(RSA.import_key)
    RsaKey = RSA.RsaKey


_svc_mod.RSA = _FastRSA


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.bucket = os.path.join(self.td, "bucket")
        self.svc = SecureCloudService(
            os.path.join(self.td, "d"),
            LocalCloudBackend(self.bucket),
            max_failed=3,
            lock_seconds=300,
        )
        for u in ("alice", "bob", "mallory"):
            self.svc.register(u, f"{u}-password-1")
        self.alice = self.svc.login("alice", "alice-password-1")
        self.bob = self.svc.login("bob", "bob-password-1")
        self.mallory = self.svc.login("mallory", "mallory-password-1")
        self.src = os.path.join(self.td, "secret.txt")
        with open(self.src, "wb") as f:
            f.write(SECRET)
        self.fid = self.svc.upload(self.alice, self.src, "payroll.txt")["file_id"]

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def _wrapped_key_check(self):
        # Bob's private key cannot unwrap Alice's wrapped key
        with self.svc.db.conn() as c:
            wrapped = c.execute(
                "SELECT wrapped_key FROM access WHERE file_id=? AND username='alice'",
                (self.fid,),
            ).fetchone()["wrapped_key"]
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256

        with self.assertRaises(ValueError):
            PKCS1_OAEP.new(self.bob.private_key, hashAlgo=SHA256).decrypt(wrapped)

    def blob_path(self):
        return os.path.join(self.bucket, f"{self.fid}.enc")

    def dl(self, session, fid=None):
        out = os.path.join(self.td, "out.bin")
        self.svc.download(session, fid or self.fid, out)
        return open(out, "rb").read()


class TestCryptoCorrectness(unittest.TestCase):
    def test_roundtrip_edge_sizes(self):
        with tempfile.TemporaryDirectory() as td:
            for n in (0, 1, 7, 8, 9, 4095, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 5):
                src, enc, dec = (os.path.join(td, x) for x in "sed")
                data = os.urandom(n)
                open(src, "wb").write(data)
                fk = generate_file_key()
                encrypt_file(src, enc, fk, b"id")
                decrypt_file(enc, dec, fk, b"id")
                self.assertEqual(open(dec, "rb").read(), data, f"size {n}")

    def test_generated_keys_are_valid_3key_3des(self):
        for _ in range(50):
            k = generate_file_key().des_key
            self.assertEqual(len(k), 24)
            self.assertEqual(len({k[:8], k[8:16], k[16:]}), 3)  # three independent keys
            DES3.new(k, DES3.MODE_ECB)


class TestA_UnauthorizedAccess(Base):
    def test_owner_can_download(self):
        self.assertEqual(self.dl(self.alice), SECRET)

    def test_other_user_denied(self):
        with self.assertRaises(AccessDenied):
            self.dl(self.mallory)

    def test_nonexistent_and_forbidden_look_identical(self):
        with self.assertRaises(AccessDenied) as a:
            self.dl(self.mallory)
        with self.assertRaises(AccessDenied) as b:
            self.dl(self.mallory, "0" * 32)
        self.assertEqual(str(a.exception), str(b.exception))  # no existence oracle

    def test_non_owner_cannot_share_or_delete(self):
        self.svc.share(self.alice, self.fid, "bob")
        with self.assertRaises(AccessDenied):
            self.svc.share(self.bob, self.fid, "mallory")
        with self.assertRaises(AccessDenied):
            self.svc.delete(self.bob, self.fid)

    def test_sharing_grants_access(self):
        self.svc.share(self.alice, self.fid, "bob")
        self.assertEqual(self.dl(self.bob), SECRET)

    def test_revocation_denies_and_rotates_key(self):
        self.svc.share(self.alice, self.fid, "bob")
        # Bob captures the key he legitimately held + the old ciphertext
        old_fk = self.svc._file_key(self.bob, self.fid)
        old_blob = open(self.blob_path(), "rb").read()
        self.svc.revoke(self.alice, self.fid, "bob")
        with self.assertRaises(AccessDenied):
            self.dl(self.bob)
        # blob in the cloud changed and Bob's stale key no longer opens it
        new_blob = open(self.blob_path(), "rb").read()
        self.assertNotEqual(old_blob, new_blob)
        tmp = os.path.join(self.td, "x")
        with self.assertRaises(IntegrityError):
            decrypt_file(self.blob_path(), tmp, old_fk, self.fid.encode())
        self.assertEqual(self.dl(self.alice), SECRET)  # owner unaffected

    def test_path_traversal_blocked(self):
        with self.assertRaises(ValueError):
            self.svc.cloud.get("../../etc/passwd", os.path.join(self.td, "x"))

    def test_wrong_password_cannot_login(self):
        with self.assertRaises(AuthError):
            self.svc.login("alice", "wrong-password")

    def test_audit_records_denied_attempts(self):
        with self.assertRaises(AccessDenied):
            self.dl(self.mallory)
        self.assertTrue(
            any(
                e["action"] == "access"
                and e["outcome"] == "denied"
                and e["username"] == "mallory"
                for e in self.svc.audit_log()
            )
        )


class TestB_Tampering(Base):
    def _mutate(self, fn):
        p = self.blob_path()
        b = bytearray(open(p, "rb").read())
        b = fn(b) or b
        open(p, "wb").write(bytes(b))

    def test_bit_flip_in_ciphertext_detected(self):
        self._mutate(lambda b: b.__setitem__(40, b[40] ^ 1))
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)

    def test_bit_flip_in_iv_detected(self):
        self._mutate(
            lambda b: b.__setitem__(6, b[6] ^ 1)
        )  # CBC IV flip would alter block 1 undetected w/o MAC
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)

    def test_bit_flip_in_tag_detected(self):
        self._mutate(lambda b: b.__setitem__(len(b) - 1, b[-1] ^ 1))
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)

    def test_truncation_detected(self):
        self._mutate(lambda b: b.__delitem__(slice(len(b) - 8, len(b))))
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)

    def test_block_append_detected(self):
        self._mutate(lambda b: b.extend(b"\x00" * 8))
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)

    def test_blob_swap_between_files_detected(self):
        other = os.path.join(self.td, "other.txt")
        open(other, "wb").write(b"other file")
        fid2 = self.svc.upload(self.alice, other)["file_id"]
        shutil.copy(
            os.path.join(self.bucket, f"{fid2}.enc"), self.blob_path()
        )  # provider swaps blobs
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)

    def test_no_plaintext_released_on_failure(self):
        self._mutate(lambda b: b.__setitem__(40, b[40] ^ 1))
        out = os.path.join(self.td, "out.bin")
        with self.assertRaises(IntegrityError):
            self.svc.download(self.alice, self.fid, out)
        self.assertFalse(os.path.exists(out))
        self.assertFalse(os.path.exists(out + ".part"))

    def test_tamper_is_audited(self):
        self._mutate(lambda b: b.__setitem__(40, b[40] ^ 1))
        with self.assertRaises(IntegrityError):
            self.dl(self.alice)
        self.assertTrue(
            any(e["outcome"] == "INTEGRITY-FAILURE" for e in self.svc.audit_log())
        )


class TestC_BruteForce(Base):
    def test_online_guessing_triggers_lockout(self):
        for _ in range(3):
            with self.assertRaises(AuthError):
                self.svc.login("alice", "guess")
        with self.assertRaises(
            AccountLocked
        ):  # even the CORRECT password is refused now
            self.svc.login("alice", "alice-password-1")

    def test_wrong_key_never_decrypts(self):
        tmp = os.path.join(self.td, "x")
        for _ in range(200):
            with self.assertRaises(IntegrityError):
                decrypt_file(
                    self.blob_path(), tmp, generate_file_key(), self.fid.encode()
                )

    def test_wrapped_key_unusable_without_owners_private_key(self):
        self._wrapped_key_check()

    def test_keyspace_note(self):
        # 3-key EDE: 168 key bits nominal, ~112-bit effective (meet-in-the-middle).
        # At an (unrealistic) 10^12 keys/s, 2^112 trials take ~1.6e14 years.
        years = 2**112 / 1e12 / (3600 * 24 * 365)
        self.assertGreater(years, 1e13)


class TestD_DataLeakage(Base):
    def test_cloud_blob_has_no_plaintext(self):
        blob = open(self.blob_path(), "rb").read()
        self.assertNotIn(b"TOP-SECRET", blob)
        self.assertNotIn(SECRET[:24], blob)

    def test_cloud_sees_no_filenames(self):
        names = os.listdir(self.bucket)
        self.assertTrue(all("payroll" not in n and "secret" not in n for n in names))

    def test_same_file_twice_gives_different_ciphertext(self):
        fid2 = self.svc.upload(self.alice, self.src)["file_id"]
        a = open(self.blob_path(), "rb").read()
        b = open(os.path.join(self.bucket, f"{fid2}.enc"), "rb").read()
        self.assertNotEqual(
            a[13:-32], b[13:-32]
        )  # fresh key + IV => no dedup/pattern leak

    def test_repeated_plaintext_blocks_not_visible(self):
        src = os.path.join(self.td, "rep.bin")
        open(src, "wb").write(b"A" * 8 * 1000)
        fid = self.svc.upload(self.alice, src)["file_id"]
        ct = open(os.path.join(self.bucket, f"{fid}.enc"), "rb").read()[13:-32]
        blocks = [ct[i : i + 8] for i in range(0, len(ct), 8)]
        self.assertEqual(
            len(set(blocks)), len(blocks)
        )  # CBC hides repetition (ECB would not)

    def test_db_holds_no_plaintext_keys_or_passwords(self):
        raw = open(os.path.join(self.td, "d", "metadata.db"), "rb").read()
        self.assertNotIn(b"alice-password-1", raw)
        self.assertNotIn(self.svc._file_key(self.alice, self.fid).des_key, raw)

    def test_private_key_is_encrypted_at_rest(self):
        with self.svc.db.conn() as c:
            blob = c.execute(
                "SELECT enc_private_key FROM users WHERE username='alice'"
            ).fetchone()[0]
        self.assertIn(b"ENCRYPTED PRIVATE KEY", blob)

    def test_stolen_database_and_bucket_alone_are_useless(self):
        # attacker has blob + wrapped keys but no private key: cannot recover a file key
        self._wrapped_key_check()

    def test_temp_dirs_are_cleaned(self):
        before = set(os.listdir(tempfile.gettempdir()))
        self.dl(self.alice)
        leaked = [
            n
            for n in set(os.listdir(tempfile.gettempdir())) - before
            if n.startswith("tmp")
        ]
        self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()
