# Decentralized Microgrid Energy Trading Engine

Modern Cryptography mini-project: peer-to-peer energy trading where every voucher is
**signed with RSA**, **encrypted with ElGamal**, checked against the meter and agreed by a
**3-node simulated ledger**. Backend and cryptography are pure Python (FastAPI). The website
is a single page served by the same app.

## Run

```bash
pip install -r requirements.txt
python run.py            # open http://127.0.0.1:8000
python -m pytest         # run the test suite
```

The first start generates a 1024-bit ElGamal safe prime (a few seconds) and caches it in
`app/elgamal_params.json`.

## Layout

| File | What it does |
| --- | --- |
| `app/crypto_rsa.py` | Miller-Rabin, RSA key generation, PKCS#1 v1.5 SHA-256 sign and verify |
| `app/crypto_elgamal.py` | Safe-prime group, ElGamal key generation, block encryption and decryption |
| `app/engine.py` | Participants, voucher creation, 6-step verification pipeline, ledger nodes, consensus, attack lab |
| `app/toy_math.py` | Small-number RSA and ElGamal walkthroughs (Euler's theorem, primitive roots, DLP) |
| `app/benchmark.py` | Timing comparison of RSA and ElGamal |
| `app/main.py` | REST API and static site |
| `static/index.html` | The website (slides content, simulator, math lab, benchmark) |
| `tests/test_engine.py` | Crypto round trips, every attack rejected, consensus with faulty nodes |

## Voucher and pipeline

1. **Trade request** – seller, buyer, kWh, price.
2. **Secure creation** – fields are canonicalized to JSON, signed with the seller's RSA key, and the
   payload `{qty, price, meter}` is ElGamal-encrypted to the network key.
3. **Verification** – decrypt telemetry, check nonce and timestamp (120 s window), verify RSA signature,
   check ledger balance against the meter oracle, check buyer funds, then ledger consensus.
4. **Settlement** – 2 of 3 nodes must accept; each node commits a hash-linked block.

## Attacks covered

Price tampering, signature forgery, replay, delayed delivery, over-claiming energy, ciphertext
corruption. A faulty node (votes the opposite way) cannot change the result alone.

## API

`GET /api/state` · `POST /api/trade` · `POST /api/attack` · `GET /api/attacks` · `POST /api/reset` ·
`POST /api/nodes/{i}/toggle` · `GET /api/toy/rsa` · `GET /api/toy/elgamal` · `GET /api/benchmark` ·
`GET /api/sample-voucher`

## Notes

Educational implementation: textbook-style primitives, a shared network decryption key and
simulated meters. Do not use it to protect real data.
