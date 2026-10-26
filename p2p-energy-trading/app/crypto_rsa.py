"""RSA key generation and signatures, written from scratch for the course.

Signature scheme: RSASSA-PKCS1-v1_5 with SHA-256 (the same padding layout that
real systems use), implemented with Python big integers only.

    sign:    s = EM^d mod n
    verify:  EM == s^e mod n

Educational code. For production use a vetted library.
"""
from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]

# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017, section 9.2)
_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Random prime with the top two bits set so p*q has exactly 2*bits bits."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    def public(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)


def generate_keypair(bits: int = 1024, e: int = 65537) -> RSAPrivateKey:
    """Generate an RSA key pair: n = p*q, d = e^-1 mod lcm(p-1, q-1)."""
    if bits < 512 or bits % 2:
        raise ValueError("bits must be an even number >= 512")
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if math.gcd(e, lam) != 1:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        return RSAPrivateKey(n=n, e=e, d=pow(e, -1, lam), p=p, q=q)


def _encode(message: bytes, k: int) -> int:
    """EMSA-PKCS1-v1_5 encoding of SHA-256(message) into k bytes."""
    t = _DIGEST_INFO + hashlib.sha256(message).digest()
    pad_len = k - len(t) - 3
    if pad_len < 8:
        raise ValueError("key too small for SHA-256 PKCS#1 signatures")
    return int.from_bytes(b"\x00\x01" + b"\xff" * pad_len + b"\x00" + t, "big")


def sign(message: bytes, key: RSAPrivateKey) -> bytes:
    k = (key.n.bit_length() + 7) // 8
    m = _encode(message, k)
    return pow(m, key.d, key.n).to_bytes(k, "big")


def verify(message: bytes, signature: bytes, key: RSAPublicKey) -> bool:
    k = key.size_bytes
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= key.n:
        return False
    try:
        expected = _encode(message, k)
    except ValueError:
        return False
    return pow(s, key.e, key.n) == expected
