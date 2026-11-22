#!/usr/bin/env python3
"""CLI for the 3DES secure cloud storage system.

  python main.py register alice
  python main.py upload alice report.pdf
  python main.py list alice
  python main.py share alice <file_id> bob
  python main.py download bob <file_id> out.pdf
  python main.py revoke alice <file_id> bob
  python main.py delete alice <file_id>
  python main.py audit alice

Passwords are prompted securely (or set SECURECLOUD_PASSWORD for scripting).
Data lives in ./cloud_data (override with SECURECLOUD_HOME).
"""

import argparse
import getpass
import os
import sys

from securecloud import (
    AccessDenied,
    AccountLocked,
    AuthError,
    IntegrityError,
    LocalCloudBackend,
    SecureCloudService,
)

HOME = os.environ.get("SECURECLOUD_HOME", "cloud_data")


def get_service():
    return SecureCloudService(HOME, LocalCloudBackend(os.path.join(HOME, "bucket")))


def pw(prompt="Password: "):
    return os.environ.get("SECURECLOUD_PASSWORD") or getpass.getpass(prompt)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, args in {
        "register": ["user"],
        "upload": ["user", "path"],
        "download": ["user", "file_id", "dest"],
        "share": ["user", "file_id", "target"],
        "revoke": ["user", "file_id", "target"],
        "delete": ["user", "file_id"],
        "list": ["user"],
        "audit": ["user"],
    }.items():
        p = sub.add_parser(name)
        for a in args:
            p.add_argument(a)
    a = ap.parse_args()
    svc = get_service()
    try:
        if a.cmd == "register":
            p1 = pw("Choose password (min 8 chars): ")
            svc.register(a.user, p1)
            print(f"registered {a.user}")
            return
        s = svc.login(a.user, pw())
        if a.cmd == "upload":
            r = svc.upload(s, a.path)
            print(
                f"uploaded. file_id={r['file_id']}  plain={r['plain_size']}B  cloud={r['cloud_size']}B  "
                f"encrypt={r['encrypt_s']*1000:.1f}ms upload={r['upload_s']*1000:.1f}ms"
            )
        elif a.cmd == "download":
            r = svc.download(s, a.file_id, a.dest)
            print(
                f"saved to {a.dest} (download={r['download_s']*1000:.1f}ms decrypt={r['decrypt_s']*1000:.1f}ms)"
            )
        elif a.cmd == "share":
            svc.share(s, a.file_id, a.target)
            print("shared")
        elif a.cmd == "revoke":
            svc.revoke(s, a.file_id, a.target)
            print("revoked (file key rotated, blob re-encrypted)")
        elif a.cmd == "delete":
            svc.delete(s, a.file_id)
            print("deleted")
        elif a.cmd == "list":
            for f in svc.list_files(s):
                print(
                    f"{f['file_id']}  {f['name']:<30} owner={f['owner']:<10} {f['plain_size']}B"
                )
        elif a.cmd == "audit":
            for e in reversed(svc.audit_log()):
                print(e["id"], e["username"], e["action"], e["target"], e["outcome"])
    except (
        AuthError,
        AccountLocked,
        AccessDenied,
        IntegrityError,
        ValueError,
        FileNotFoundError,
    ) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
