"""Trading engine: participants, signed+encrypted energy vouchers, verification
pipeline, a 3-node simulated ledger with majority consensus, and an attack lab.

Voucher format
--------------
Clear fields:   seller, buyer, nonce, timestamp
Encrypted:      {qty_kwh, price_per_kwh, meter_kwh}   (ElGamal, to the network key)
Signature:      RSA over canonical JSON of all fields (seller signs)
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass

from . import crypto_elgamal as eg
from . import crypto_rsa as rsa

FRESHNESS_SECONDS = 120
RSA_BITS = 1024
ELGAMAL_BITS = 1024
NODE_NAMES = ["Node A", "Node B", "Node C"]

SEED = [
    ("asha", "Asha Verma", "Solar prosumer · 5 kW rooftop", 42.0, 500.0),
    ("ravi", "Ravi Iyer", "Solar + battery prosumer", 18.5, 800.0),
    ("meera", "Meera Nair", "Household consumer", 3.0, 1500.0),
    ("kabir", "Kabir Singh", "Wind microturbine prosumer", 27.0, 300.0),
]

ATTACKS = {
    "tamper": {
        "title": "Tamper with price",
        "who": "Man in the middle",
        "idea": "Re-encrypts the voucher with a 10x lower price using the public key, but cannot re-sign it.",
    },
    "forge": {
        "title": "Forge seller signature",
        "who": "Dishonest buyer",
        "idea": "Signs a voucher in the seller's name with the buyer's own RSA key.",
    },
    "replay": {
        "title": "Replay old voucher",
        "who": "Eavesdropper",
        "idea": "Submits a valid voucher, then sends the identical bytes again.",
    },
    "stale": {
        "title": "Delay a voucher",
        "who": "Network attacker",
        "idea": "Holds a correctly signed voucher for an hour before delivering it.",
    },
    "overclaim": {
        "title": "Claim energy not owned",
        "who": "Dishonest seller",
        "idea": "Signs a valid voucher for more kWh than the ledger balance and the meter allow.",
    },
    "corrupt": {
        "title": "Corrupt ciphertext",
        "who": "Faulty link",
        "idea": "Flips a bit inside the ElGamal ciphertext in transit.",
    },
}


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short(h: str, head: int = 16, tail: int = 6) -> str:
    return h if len(h) <= head + tail + 1 else f"{h[:head]}…{h[-tail:]}"


@dataclass
class Participant:
    id: str
    name: str
    role: str
    start_kwh: float
    start_credit: float
    key: rsa.RSAPrivateKey


class Rejection(Exception):
    pass


class LedgerNode:
    """One replica: its own balances, seen-nonce set and hash-linked chain."""

    def __init__(self, name: str):
        self.name = name
        self.byzantine = False
        self.reset({}, {})

    def reset(self, kwh: dict, credit: dict) -> None:
        self.balances = dict(kwh)
        self.credits = dict(credit)
        self.seen: set[str] = set()
        self.chain = [self._block(0, "0" * 64, "genesis", {})]

    @staticmethod
    def _block(index: int, prev: str, tx_id: str, summary: dict) -> dict:
        body = {"index": index, "prev": prev, "tx_id": tx_id, "summary": summary,
                "timestamp": round(time.time(), 3)}
        return {**body, "hash": sha256_hex(canonical(body))}

    def commit(self, tx_id: str, nonce: str, seller: str, buyer: str, qty: float, price: float) -> None:
        cost = round(qty * price, 6)
        self.balances[seller] = round(self.balances[seller] - qty, 6)
        self.balances[buyer] = round(self.balances[buyer] + qty, 6)
        self.credits[buyer] = round(self.credits[buyer] - cost, 6)
        self.credits[seller] = round(self.credits[seller] + cost, 6)
        self.seen.add(nonce)
        summary = {"seller": seller, "buyer": buyer, "qty_kwh": qty, "price_per_kwh": price}
        self.chain.append(self._block(len(self.chain), self.chain[-1]["hash"], tx_id, summary))

    def chain_valid(self) -> bool:
        for i, blk in enumerate(self.chain):
            body = {k: blk[k] for k in ("index", "prev", "tx_id", "summary", "timestamp")}
            if sha256_hex(canonical(body)) != blk["hash"]:
                return False
            if i and blk["prev"] != self.chain[i - 1]["hash"]:
                return False
        return True


def run_checks(env: dict, node: LedgerNode, registry: dict, oracle: dict,
               net_priv: eg.ElGamalPrivateKey, now: float) -> tuple[list[dict], dict]:
    """Run the verification pipeline against one node's state."""
    steps: list[dict] = []
    ctx: dict = {}
    failed = False

    def step(step_id: str, title: str, fn) -> None:
        nonlocal failed
        if failed:
            steps.append({"id": step_id, "title": title, "status": "skipped",
                          "detail": "Not evaluated because an earlier check failed.", "ms": 0})
            return
        t0 = time.perf_counter()
        try:
            detail, status = fn(), "pass"
        except Rejection as exc:
            detail, status, failed = str(exc), "fail", True
        steps.append({"id": step_id, "title": title, "status": status, "detail": detail,
                      "ms": round((time.perf_counter() - t0) * 1000, 2)})

    def decrypt_step() -> str:
        try:
            raw = eg.decrypt(net_priv, env["ciphertext"])
            data = json.loads(raw.decode("utf-8"))
            ctx["qty"] = float(data["qty_kwh"])
            ctx["price"] = float(data["price_per_kwh"])
            ctx["meter"] = float(data["meter_kwh"])
        except Exception:
            raise Rejection("The ElGamal ciphertext does not decrypt to a valid trade payload.")
        return f"Decrypted {len(raw)} bytes from {len(env['ciphertext']['chunks'])} ElGamal block(s)."

    def fresh_step() -> str:
        nonce, ts = env.get("nonce"), env.get("timestamp")
        if not isinstance(nonce, str) or len(nonce) < 16 or not isinstance(ts, (int, float)):
            raise Rejection("Nonce or timestamp is missing or malformed.")
        if nonce in node.seen:
            raise Rejection("This nonce was already used. The voucher is a replay.")
        age = now - ts
        if abs(age) > FRESHNESS_SECONDS:
            raise Rejection(f"Timestamp is {int(abs(age))} s away from network time (limit {FRESHNESS_SECONDS} s).")
        return f"Nonce unseen and timestamp within {FRESHNESS_SECONDS} s of network time."

    def signature_step() -> str:
        pub = registry.get(env.get("seller"))
        if pub is None or env.get("buyer") not in registry:
            raise Rejection("Seller or buyer is not a registered participant.")
        signed = signed_fields(env, ctx)
        try:
            sig = bytes.fromhex(env["signature"])
        except (KeyError, ValueError):
            raise Rejection("Signature is missing or not valid hex.")
        if not rsa.verify(canonical(signed), sig, pub):
            raise Rejection("RSA signature does not match the seller's public key and the decrypted trade data.")
        return f"RSA-{pub.bits} signature (PKCS#1 v1.5, SHA-256) verifies for {env['seller']}."

    def energy_step() -> str:
        seller, qty, price, meter = env["seller"], ctx["qty"], ctx["price"], ctx["meter"]
        if env["seller"] == env["buyer"]:
            raise Rejection("Seller and buyer must be different participants.")
        if not (qty > 0 and price > 0):
            raise Rejection("Quantity and price must be positive.")
        balance = node.balances.get(seller, 0.0)
        if qty > balance + 1e-9:
            raise Rejection(f"Voucher claims {qty} kWh but the ledger balance of {seller} is {balance} kWh.")
        physical = oracle[seller]
        if abs(meter - physical) > 0.01:
            raise Rejection(f"Signed telemetry says {meter} kWh but the meter oracle reads {physical} kWh.")
        if qty > physical + 1e-9:
            raise Rejection(f"Voucher claims {qty} kWh but the meter only shows {physical} kWh.")
        return f"{qty} kWh is within ledger balance ({balance} kWh) and meter reading ({physical} kWh)."

    def funds_step() -> str:
        cost = round(ctx["qty"] * ctx["price"], 6)
        credit = node.credits.get(env["buyer"], 0.0)
        if cost > credit + 1e-9:
            raise Rejection(f"Trade costs ₹{cost} but the buyer only has ₹{credit}.")
        return f"Buyer can pay ₹{cost} (balance ₹{credit})."

    step("decrypt", "Decrypt telemetry (ElGamal)", decrypt_step)
    step("fresh", "Check nonce and timestamp", fresh_step)
    step("signature", "Verify seller signature (RSA)", signature_step)
    step("energy", "Check energy balance and meter", energy_step)
    step("funds", "Check buyer funds", funds_step)
    return steps, ctx


def signed_fields(env: dict, payload: dict) -> dict:
    return {
        "seller": env["seller"], "buyer": env["buyer"],
        "nonce": env["nonce"], "timestamp": env["timestamp"],
        "qty_kwh": payload["qty"], "price_per_kwh": payload["price"], "meter_kwh": payload["meter"],
    }


class Engine:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.group = eg.get_group(ELGAMAL_BITS)
        self.net_priv = eg.generate_keypair(self.group)
        self.net_pub = self.net_priv.public()
        self.participants = {
            pid: Participant(pid, name, role, kwh, credit, rsa.generate_keypair(RSA_BITS))
            for pid, name, role, kwh, credit in SEED
        }
        self.registry = {pid: p.key.public() for pid, p in self.participants.items()}
        self.nodes = [LedgerNode(n) for n in NODE_NAMES]
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self) -> None:
        with self.lock:
            kwh = {pid: p.start_kwh for pid, p in self.participants.items()}
            credit = {pid: p.start_credit for pid, p in self.participants.items()}
            self.oracle = dict(kwh)
            for node in self.nodes:
                node.byzantine = False
                node.reset(kwh, credit)
            self.log: list[dict] = []
            self.stats = {"accepted": 0, "rejected": 0, "volume_kwh": 0.0}

    def toggle_node(self, idx: int) -> bool:
        with self.lock:
            node = self.nodes[idx]
            node.byzantine = not node.byzantine
            return node.byzantine

    def state(self) -> dict:
        with self.lock:
            lead = self.nodes[0]
            people = []
            for pid, p in self.participants.items():
                pub = p.key.public()
                people.append({
                    "id": pid, "name": p.name, "role": p.role,
                    "ledger_kwh": lead.balances[pid], "meter_kwh": self.oracle[pid],
                    "credit": lead.credits[pid],
                    "rsa": {"bits": pub.bits, "e": pub.e, "n": short(format(pub.n, "x"), 20, 8)},
                })
            nodes = [{
                "name": n.name, "byzantine": n.byzantine, "height": len(n.chain) - 1,
                "head": short(n.chain[-1]["hash"], 12, 4), "valid": n.chain_valid(),
                "blocks": [{"index": b["index"], "hash": short(b["hash"], 10, 4), "prev": short(b["prev"], 10, 4),
                            "tx_id": b["tx_id"], "summary": b["summary"]} for b in n.chain[-5:]],
            } for n in self.nodes]
            return {
                "participants": people, "nodes": nodes, "log": self.log[-12:][::-1], "stats": self.stats,
                "config": {
                    "rsa_bits": RSA_BITS, "elgamal_bits": self.group.bits,
                    "freshness_seconds": FRESHNESS_SECONDS, "quorum": len(self.nodes) // 2 + 1,
                },
            }

    # --------------------------------------------------------------- vouchers
    def _build(self, claimed_seller: str, buyer: str, qty: float, price: float, *,
               signer: str | None = None, ts: float | None = None, meter: float | None = None) -> tuple[dict, dict]:
        self._need(claimed_seller)
        self._need(buyer)
        signer_key = self.participants[signer or claimed_seller].key
        meter = self.oracle[claimed_seller] if meter is None else meter
        env = {
            "seller": claimed_seller, "buyer": buyer,
            "nonce": secrets.token_hex(16),
            "timestamp": round(time.time() if ts is None else ts, 3),
        }
        payload = {"qty": qty, "price": price, "meter": meter}
        t0 = time.perf_counter()
        env["signature"] = rsa.sign(canonical(signed_fields(env, payload)), signer_key).hex()
        t1 = time.perf_counter()
        env["ciphertext"] = eg.encrypt(self.net_pub, canonical(
            {"qty_kwh": qty, "price_per_kwh": price, "meter_kwh": meter}))
        t2 = time.perf_counter()
        return env, {"sign_ms": round((t1 - t0) * 1000, 2), "encrypt_ms": round((t2 - t1) * 1000, 2)}

    def _need(self, pid: str) -> None:
        if pid not in self.participants:
            raise KeyError(f"Unknown participant '{pid}'.")

    # ----------------------------------------------------------------- submit
    def submit(self, env: dict, kind: str, qty: float, price: float, build_ms: dict | None = None) -> dict:
        with self.lock:
            now = time.time()
            votes, gateway_steps, gateway_ctx = [], [], {}
            for i, node in enumerate(self.nodes):
                steps, ctx = run_checks(env, node, self.registry, self.oracle, self.net_priv, now)
                ok = all(s["status"] == "pass" for s in steps)
                vote = ok != node.byzantine  # a faulty node votes the opposite way
                reason = next((s["detail"] for s in steps if s["status"] == "fail"), "All checks passed.")
                votes.append({"node": node.name, "vote": "accept" if vote else "reject",
                              "faulty": node.byzantine, "reason": reason})
                if i == 0:
                    gateway_steps, gateway_ctx = steps, ctx
            yes = sum(v["vote"] == "accept" for v in votes)
            quorum = len(self.nodes) // 2 + 1
            accepted = yes >= quorum and bool(gateway_ctx)
            tx_id = sha256_hex(env["signature"].encode() + env["nonce"].encode())[:16] \
                if isinstance(env.get("signature"), str) and isinstance(env.get("nonce"), str) else "n/a"
            gateway_steps.append({
                "id": "consensus", "title": "Ledger consensus (2 of 3)",
                "status": "pass" if accepted else "fail",
                "detail": f"{yes} of {len(self.nodes)} nodes voted to accept (quorum is {quorum}).", "ms": 0,
            })
            reason = next((s["detail"] for s in gateway_steps if s["status"] == "fail"), "Settled on all nodes.")
            if accepted:
                q, p = gateway_ctx["qty"], gateway_ctx["price"]
                for node in self.nodes:
                    node.commit(tx_id, env["nonce"], env["seller"], env["buyer"], q, p)
                self.oracle[env["seller"]] = round(self.oracle[env["seller"]] - q, 6)
                self.oracle[env["buyer"]] = round(self.oracle[env["buyer"]] + q, 6)
                self.stats["accepted"] += 1
                self.stats["volume_kwh"] = round(self.stats["volume_kwh"] + q, 6)
            else:
                self.stats["rejected"] += 1
            timings = dict(build_ms or {})
            timings["decrypt_ms"] = next((s["ms"] for s in gateway_steps if s["id"] == "decrypt"), 0)
            timings["verify_ms"] = next((s["ms"] for s in gateway_steps if s["id"] == "signature"), 0)
            result = {
                "accepted": accepted, "tx_id": tx_id, "kind": kind, "reason": reason,
                "steps": gateway_steps, "votes": votes, "envelope": self._preview(env), "timings_ms": timings,
            }
            self.log.append({
                "time": time.strftime("%H:%M:%S"), "kind": kind, "seller": env.get("seller"),
                "buyer": env.get("buyer"), "qty": qty, "price": price,
                "accepted": accepted, "reason": reason, "tx_id": tx_id,
            })
            return result

    def _preview(self, env: dict) -> dict:
        chunks = env["ciphertext"]["chunks"]
        return {
            "seller": env["seller"], "buyer": env["buyer"], "nonce": env["nonce"], "timestamp": env["timestamp"],
            "signature": short(env["signature"], 40, 8), "signature_bytes": len(env["signature"]) // 2,
            "ciphertext_blocks": len(chunks), "c1": short(chunks[0][0], 28, 6), "c2": short(chunks[0][1], 28, 6),
            "ciphertext_bytes": eg.ciphertext_size(env["ciphertext"], self.group),
        }

    # -------------------------------------------------------------- public ops
    def sample_voucher(self) -> dict:
        """Build a signed, encrypted voucher without submitting it (used by the hero card)."""
        with self.lock:
            env, _ = self._build("asha", "meera", 0.5, 6.5)
            return self._preview(env)

    def honest(self, seller: str, buyer: str, qty: float, price: float) -> dict:
        with self.lock:
            env, ms = self._build(seller, buyer, qty, price)
            return self.submit(env, "honest", qty, price, ms)

    def attack(self, kind: str, seller: str, buyer: str, qty: float, price: float) -> dict:
        if kind not in ATTACKS:
            raise ValueError(f"Unknown attack '{kind}'.")
        with self.lock:
            self._need(seller)
            self._need(buyer)
            preface = None
            ms: dict = {}
            if kind == "tamper":
                env, ms = self._build(seller, buyer, qty, price)
                cheap = round(price * 0.1, 3)
                env["ciphertext"] = eg.encrypt(self.net_pub, canonical(
                    {"qty_kwh": qty, "price_per_kwh": cheap, "meter_kwh": self.oracle[seller]}))
            elif kind == "forge":
                env, ms = self._build(seller, buyer, qty, price, signer=buyer)
            elif kind == "replay":
                env, ms = self._build(seller, buyer, qty, price)
                first = self.submit(env, "replay (original)", qty, price, ms)
                preface = {"accepted": first["accepted"], "tx_id": first["tx_id"], "reason": first["reason"]}
            elif kind == "stale":
                env, ms = self._build(seller, buyer, qty, price, ts=time.time() - 3600)
            elif kind == "overclaim":
                qty = round(self.nodes[0].balances[seller] * 2 + 10, 3)
                env, ms = self._build(seller, buyer, qty, price, meter=qty)
            else:  # corrupt
                env, ms = self._build(seller, buyer, qty, price)
                c2 = int(env["ciphertext"]["chunks"][0][1], 16) ^ 1
                env["ciphertext"]["chunks"][0][1] = format(c2, "x")
            result = self.submit(env, kind, qty, price, ms)
            result["attack"] = {"kind": kind, **ATTACKS[kind]}
            result["preface"] = preface
            return result
