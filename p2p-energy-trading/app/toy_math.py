"""Small-number walkthroughs of RSA and ElGamal for the "Mathematical Techniques" section.

Every step is returned with its formula and value so the UI can show the arithmetic.
"""
from __future__ import annotations

import math


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def prime_factors(n: int) -> list[int]:
    out, d = [], 2
    while d * d <= n:
        if n % d == 0:
            out.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        out.append(n)
    return out


def euler_phi(n: int) -> int:
    result = n
    for f in prime_factors(n):
        result = result // f * (f - 1)
    return result


def primitive_roots(p: int) -> list[int]:
    factors = prime_factors(p - 1)
    return [g for g in range(2, p) if all(pow(g, (p - 1) // f, p) != 1 for f in factors)]


def _step(label: str, formula: str, value) -> dict:
    return {"label": label, "formula": formula, "value": str(value)}


def toy_rsa(p: int, q: int, m: int, e: int | None = None) -> dict:
    if not (3 <= p <= 100_000 and 3 <= q <= 100_000):
        raise ValueError("Choose p and q between 3 and 100000.")
    if not is_prime(p):
        raise ValueError(f"p = {p} is not prime.")
    if not is_prime(q):
        raise ValueError(f"q = {q} is not prime.")
    if p == q:
        raise ValueError("p and q must be different primes.")
    n, phi = p * q, (p - 1) * (q - 1)
    if not 1 < m < n:
        raise ValueError(f"Message m must satisfy 1 < m < n = {n}.")
    if e is None:
        e = next((c for c in (65537, 17, 11, 7, 5, 3) if c < phi and math.gcd(c, phi) == 1), None)
        if e is None:
            raise ValueError("No usable public exponent for these primes. Try larger primes.")
    elif not (1 < e < phi and math.gcd(e, phi) == 1):
        raise ValueError(f"e must satisfy 1 < e < {phi} and gcd(e, {phi}) = 1.")
    d = pow(e, -1, phi)
    c = pow(m, e, n)
    back = pow(c, d, n)
    s = pow(m, d, n)
    verified = pow(s, e, n)
    steps = [
        _step("Modulus", f"n = p × q = {p} × {q}", n),
        _step("Euler totient", f"φ(n) = (p−1)(q−1) = {p - 1} × {q - 1}", phi),
        _step("Public exponent", f"e with gcd(e, φ(n)) = 1", e),
        _step("Private exponent", f"d = e⁻¹ mod φ(n), so e·d mod φ(n) = {(e * d) % phi}", d),
        _step("Encrypt", f"c = m^e mod n = {m}^{e} mod {n}", c),
        _step("Decrypt", f"c^d mod n = {c}^{d} mod {n}", back),
        _step("Sign", f"s = m^d mod n = {m}^{d} mod {n}", s),
        _step("Verify", f"s^e mod n = {s}^{e} mod {n}", verified),
    ]
    euler = None
    if math.gcd(m, n) == 1:
        euler = {
            "formula": f"m^φ(n) mod n = {m}^{phi} mod {n}",
            "value": pow(m, phi, n),
            "note": "Euler's theorem: this equals 1 whenever gcd(m, n) = 1, which is why decryption undoes encryption.",
        }
    return {
        "steps": steps,
        "euler": euler,
        "ok": back == m and verified == m,
        "public": {"n": n, "e": e},
        "private": {"d": d, "p": p, "q": q},
    }


def toy_elgamal(p: int, g: int, x: int, k: int, m: int) -> dict:
    if not 5 <= p <= 2_000_000:
        raise ValueError("Choose a prime p between 5 and 2000000.")
    if not is_prime(p):
        raise ValueError(f"p = {p} is not prime.")
    roots = primitive_roots(p)
    if g not in roots:
        sample = ", ".join(str(r) for r in roots[:8])
        raise ValueError(f"g = {g} is not a primitive root mod {p}. Try one of: {sample}.")
    if not 1 <= x <= p - 2:
        raise ValueError(f"Private key x must be between 1 and {p - 2}.")
    if not 1 <= k <= p - 2:
        raise ValueError(f"Ephemeral key k must be between 1 and {p - 2}.")
    if not 1 <= m <= p - 1:
        raise ValueError(f"Message m must be between 1 and {p - 1}.")
    y = pow(g, x, p)
    c1 = pow(g, k, p)
    shared = pow(y, k, p)
    c2 = (m * shared) % p
    shared_dec = pow(c1, x, p)
    back = (c2 * pow(shared_dec, -1, p)) % p
    steps = [
        _step("Public key", f"y = g^x mod p = {g}^{x} mod {p}", y),
        _step("First part", f"c₁ = g^k mod p = {g}^{k} mod {p}", c1),
        _step("Shared secret", f"s = y^k mod p = {y}^{k} mod {p}", shared),
        _step("Second part", f"c₂ = m · s mod p = {m} × {shared} mod {p}", c2),
        _step("Recover secret", f"s = c₁^x mod p = {c1}^{x} mod {p}", shared_dec),
        _step("Decrypt", f"m = c₂ · s⁻¹ mod p = {c2} × {shared_dec}⁻¹ mod {p}", back),
    ]
    table = [{"i": i, "value": pow(g, i, p)} for i in range(0, min(p - 1, 12) + 1)]
    return {
        "steps": steps,
        "ok": back == m,
        "ciphertext": [c1, c2],
        "public_key": y,
        "primitive_root_count": len(roots),
        "primitive_roots": roots[:10],
        "power_table": table,
        "dlp_note": f"To recover x from y = {y}, an attacker must solve g^x ≡ {y} (mod {p}). "
                    f"Brute force tries up to {p - 1} exponents here; for a 1024-bit prime that is hopeless.",
    }
