"""ElGamal encryption over a safe-prime group, written from scratch.

Group:  p = 2q + 1 with p and q prime, generator g = 4 of the order-q subgroup
        (the quadratic residues mod p).

    keygen:   x random in [1, q-1],  y = g^x mod p
    encrypt:  k random,  c1 = g^k mod p,  c2 = m * y^k mod p
    decrypt:  m = c2 * (c1^x)^-1 mod p

Security rests on the Discrete Logarithm Problem (DDH in the subgroup).
Messages are split into blocks, each mapped into the subgroup and back.

Educational code. For production use a vetted library.
"""
from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path

from .crypto_rsa import is_probable_prime

PARAMS_FILE = Path(__file__).with_name("elgamal_params.json")
_SIEVE_PRIMES = [p for p in range(3, 20000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]
_lock = threading.Lock()
_cache: dict[int, "Group"] = {}


@dataclass(frozen=True)
class Group:
    p: int
    q: int
    g: int

    @property
    def bits(self) -> int:
        return self.p.bit_length()

    @property
    def block_bytes(self) -> int:
        return (self.q.bit_length() - 1) // 8


@dataclass(frozen=True)
class ElGamalPublicKey:
    group: Group
    y: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
    group: Group
    x: int
    y: int

    def public(self) -> ElGamalPublicKey:
        return ElGamalPublicKey(self.group, self.y)


def generate_safe_prime(bits: int) -> int:
    """Find p = 2q+1 with p, q prime, using a sieve over a window of candidates."""
    qbits = bits - 1
    window = 1 << 17
    while True:
        base = secrets.randbits(qbits) | (1 << (qbits - 1)) | 1
        ok = bytearray([1]) * window
        for sp in _SIEVE_PRIMES:
            r = (-base * ((sp + 1) // 2)) % sp  # q = base + 2i divisible by sp
            ok[r::sp] = bytes(len(range(r, window, sp)))
            r2 = (-(2 * base + 1) * pow(4, -1, sp)) % sp  # p = 2q + 1 divisible by sp
            ok[r2::sp] = bytes(len(range(r2, window, sp)))
        for i in range(window):
            if not ok[i]:
                continue
            q = base + 2 * i
            p = 2 * q + 1
            if pow(2, q - 1, q) != 1 or pow(2, p - 1, p) != 1:
                continue
            if is_probable_prime(q, 24) and is_probable_prime(p, 24):
                return p


def get_group(bits: int = 1024) -> Group:
    """Return the cached group for this size, generating (and saving) it once."""
    with _lock:
        if bits in _cache:
            return _cache[bits]
        stored: dict = {}
        if PARAMS_FILE.exists():
            try:
                stored = json.loads(PARAMS_FILE.read_text())
            except (OSError, ValueError):
                stored = {}
        entry = stored.get(str(bits))
        if entry:
            p = int(entry["p"], 16)
        else:
            p = generate_safe_prime(bits)
            stored[str(bits)] = {"p": format(p, "x")}
            try:
                PARAMS_FILE.write_text(json.dumps(stored, indent=2))
            except OSError:
                pass
        group = Group(p=p, q=(p - 1) // 2, g=4)
        _cache[bits] = group
        return group


def generate_keypair(group: Group) -> ElGamalPrivateKey:
    x = secrets.randbelow(group.q - 1) + 1
    return ElGamalPrivateKey(group=group, x=x, y=pow(group.g, x, group.p))


def _to_subgroup(m: int, group: Group) -> int:
    """Map m in [1, q] to a quadratic residue (p is 3 mod 4, so -1 is a non-residue)."""
    return m if pow(m, group.q, group.p) == 1 else group.p - m


def _from_subgroup(e: int, group: Group) -> int:
    return e if e <= group.q else group.p - e


def encrypt(pub: ElGamalPublicKey, data: bytes) -> dict:
    """Encrypt bytes block by block. Returns a JSON-friendly ciphertext."""
    group = pub.group
    size = group.block_bytes
    chunks = []
    for i in range(0, max(len(data), 1), size):
        block = data[i:i + size]
        m = int.from_bytes(block.ljust(size, b"\x00"), "big") + 1  # keep m >= 1
        k = secrets.randbelow(group.q - 1) + 1
        c1 = pow(group.g, k, group.p)
        c2 = (_to_subgroup(m, group) * pow(pub.y, k, group.p)) % group.p
        chunks.append([format(c1, "x"), format(c2, "x")])
    return {"length": len(data), "chunks": chunks}


def decrypt(priv: ElGamalPrivateKey, ciphertext: dict) -> bytes:
    group = priv.group
    size = group.block_bytes
    out = bytearray()
    for c1_hex, c2_hex in ciphertext["chunks"]:
        c1, c2 = int(c1_hex, 16), int(c2_hex, 16)
        if not (1 < c1 < group.p and 0 < c2 < group.p):
            raise ValueError("ciphertext element out of range")
        shared = pow(c1, priv.x, group.p)
        m = _from_subgroup((c2 * pow(shared, -1, group.p)) % group.p, group) - 1
        if not 0 <= m < 256 ** size:
            raise ValueError("ciphertext does not decrypt to a valid block")
        out += m.to_bytes(size, "big")
    length = int(ciphertext["length"])
    if length > len(out):
        raise ValueError("bad length")
    return bytes(out[:length])


def ciphertext_size(ciphertext: dict, group: Group) -> int:
    return len(ciphertext["chunks"]) * 2 * ((group.p.bit_length() + 7) // 8)
