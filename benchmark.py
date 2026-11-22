#!/usr/bin/env python3
"""Performance evaluation: encryption/decryption time, upload/download latency, storage overhead."""

import csv
import os
import statistics as st
import sys
import tempfile

from securecloud import LocalCloudBackend, SecureCloudService

SIZES = [
    ("1 KB", 1 << 10),
    ("100 KB", 100 << 10),
    ("1 MB", 1 << 20),
    ("10 MB", 10 << 20),
    ("50 MB", 50 << 20),
]
REPEATS = 3
# Network profiles: (label, latency_ms, bandwidth_mbps)
PROFILES = [("local-disk", 0, None), ("simulated-WAN (40ms, 50Mbps)", 40, 50)]


def run(profile):
    label, lat, bw = profile
    rows = []
    with tempfile.TemporaryDirectory() as td:
        svc = SecureCloudService(
            os.path.join(td, "d"),
            LocalCloudBackend(os.path.join(td, "bucket"), lat, bw),
        )
        svc.register("bench", "benchmark-pass-1")
        s = svc.login("bench", "benchmark-pass-1")
        for name, size in SIZES:
            src = os.path.join(td, "src.bin")
            dst = os.path.join(td, "out.bin")
            with open(src, "wb") as f:
                f.write(os.urandom(size))
            m = dict(enc=[], up=[], down=[], dec=[])
            for _ in range(REPEATS):
                u = svc.upload(s, src)
                d = svc.download(s, u["file_id"], dst)
                m["enc"].append(u["encrypt_s"])
                m["up"].append(u["upload_s"])
                m["down"].append(d["download_s"])
                m["dec"].append(d["decrypt_s"])
                assert (
                    open(src, "rb").read() == open(dst, "rb").read()
                ), "round-trip mismatch!"
            ov = u["cloud_size"] - size
            rows.append(
                dict(
                    profile=label,
                    size=name,
                    bytes=size,
                    encrypt_ms=st.mean(m["enc"]) * 1e3,
                    decrypt_ms=st.mean(m["dec"]) * 1e3,
                    upload_ms=st.mean(m["up"]) * 1e3,
                    download_ms=st.mean(m["down"]) * 1e3,
                    enc_MBps=size / st.mean(m["enc"]) / 1e6,
                    overhead_bytes=ov,
                    overhead_pct=100 * ov / size,
                )
            )
    return rows


def main():
    os.makedirs("results", exist_ok=True)
    rows = [r for p in PROFILES for r in run(p)]
    with open("results/benchmark.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    hdr = f"{'profile':<30}{'size':>8}{'enc ms':>10}{'dec ms':>10}{'up ms':>10}{'down ms':>10}{'MB/s':>8}{'ovh B':>7}{'ovh %':>9}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(
            f"{r['profile']:<30}{r['size']:>8}{r['encrypt_ms']:>10.1f}{r['decrypt_ms']:>10.1f}"
            f"{r['upload_ms']:>10.1f}{r['download_ms']:>10.1f}{r['enc_MBps']:>8.1f}"
            f"{r['overhead_bytes']:>7}{r['overhead_pct']:>9.3f}"
        )
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        loc = [r for r in rows if r["profile"] == "local-disk"]
        wan = [r for r in rows if r["profile"] != "local-disk"]
        fig, ax = plt.subplots(1, 3, figsize=(16, 4.5))
        x = [r["bytes"] for r in loc]
        ax[0].loglog(x, [r["encrypt_ms"] for r in loc], "o-", label="Encrypt")
        ax[0].loglog(
            x, [r["decrypt_ms"] for r in loc], "s-", label="Decrypt (verify+decrypt)"
        )
        ax[0].set(
            title="3DES-CBC + HMAC time vs file size", xlabel="bytes", ylabel="ms"
        )
        ax[0].legend()
        ax[0].grid(True, which="both", alpha=0.3)
        ax[1].loglog(x, [r["upload_ms"] for r in wan], "o-", label="Upload")
        ax[1].loglog(x, [r["download_ms"] for r in wan], "s-", label="Download")
        ax[1].set(
            title="Cloud latency (simulated 40ms, 50 Mbps)", xlabel="bytes", ylabel="ms"
        )
        ax[1].legend()
        ax[1].grid(True, which="both", alpha=0.3)
        ax[2].semilogx(x, [r["overhead_pct"] for r in loc], "o-")
        ax[2].set(title="Storage overhead", xlabel="bytes", ylabel="% over plaintext")
        ax[2].grid(True, which="both", alpha=0.3)
        plt.tight_layout()
        plt.savefig("results/benchmark.png", dpi=130)
        print("\nSaved results/benchmark.csv and results/benchmark.png")
    except ImportError:
        print("\nSaved results/benchmark.csv (install matplotlib for charts)")


if __name__ == "__main__":
    sys.exit(main())
