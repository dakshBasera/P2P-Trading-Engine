"""Timing comparison of the two cryptosystems for the "Comparison" objective."""
from __future__ import annotations

import time

from . import crypto_elgamal as eg
from . import crypto_rsa as rsa

PAYLOAD = b'{"meter_kwh":42.0,"price_per_kwh":6.5,"qty_kwh":4.5}' * 2  # about 100 bytes


def _avg_ms(fn, runs: int) -> float:
    start = time.perf_counter()
    for _ in range(runs):
        fn()
    return round((time.perf_counter() - start) * 1000 / runs, 3)


def run_benchmark(include_2048: bool = False) -> dict:
    rsa_rows = []
    for bits in (512, 1024, 2048) if include_2048 else (512, 1024):
        t0 = time.perf_counter()
        key = rsa.generate_keypair(bits)
        keygen = round((time.perf_counter() - t0) * 1000, 1)
        sig = rsa.sign(PAYLOAD, key)
        pub = key.public()
        rsa_rows.append({
            "bits": bits, "keygen_ms": keygen,
            "op1_ms": _avg_ms(lambda: rsa.sign(PAYLOAD, key), 30),
            "op2_ms": _avg_ms(lambda: rsa.verify(PAYLOAD, sig, pub), 30),
            "output_bytes": len(sig),
        })

    eg_rows = []
    for bits in (512, 1024):
        group = eg.get_group(bits)
        t0 = time.perf_counter()
        key = eg.generate_keypair(group)
        keygen = round((time.perf_counter() - t0) * 1000, 2)
        pub = key.public()
        ct = eg.encrypt(pub, PAYLOAD)
        eg_rows.append({
            "bits": bits, "keygen_ms": keygen,
            "op1_ms": _avg_ms(lambda: eg.encrypt(pub, PAYLOAD), 15),
            "op2_ms": _avg_ms(lambda: eg.decrypt(key, ct), 15),
            "output_bytes": eg.ciphertext_size(ct, group),
        })

    r, e = rsa_rows[min(1, len(rsa_rows) - 1)], eg_rows[-1]
    per_trade = r["op1_ms"] + e["op1_ms"] + 3 * (e["op2_ms"] + r["op2_ms"])
    return {
        "payload_bytes": len(PAYLOAD),
        "rsa": rsa_rows,
        "elgamal": eg_rows,
        "estimate": {
            "ms_per_trade": round(per_trade, 2),
            "trades_per_second": round(1000 / per_trade, 1),
            "note": "One signature and encryption, then decryption and verification on each of 3 nodes, "
                    "single-threaded pure Python.",
        },
    }
