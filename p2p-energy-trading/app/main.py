"""FastAPI application: REST API plus the single-page website."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import benchmark, engine as eng, toy_math

STATIC = Path(__file__).resolve().parent.parent / "static"
state: dict[str, eng.Engine] = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    state["engine"] = eng.Engine()  # generates RSA keys and loads the ElGamal group
    yield


app = FastAPI(title="Decentralized Microgrid Energy Trading Engine", lifespan=lifespan)


class TradeIn(BaseModel):
    seller_id: str
    buyer_id: str
    qty_kwh: float = Field(gt=0, le=1000)
    price_per_kwh: float = Field(gt=0, le=1000)


class AttackIn(TradeIn):
    kind: str


def _guard(fn, *args):
    try:
        return fn(*args)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc).strip("'\""))


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/state")
def get_state():
    return state["engine"].state()


@app.post("/api/trade")
def post_trade(body: TradeIn):
    return _guard(state["engine"].honest, body.seller_id, body.buyer_id, body.qty_kwh, body.price_per_kwh)


@app.post("/api/attack")
def post_attack(body: AttackIn):
    return _guard(state["engine"].attack, body.kind, body.seller_id, body.buyer_id,
                  body.qty_kwh, body.price_per_kwh)


@app.get("/api/sample-voucher")
def sample_voucher():
    return state["engine"].sample_voucher()


@app.get("/api/attacks")
def get_attacks():
    return [{"kind": k, **v} for k, v in eng.ATTACKS.items()]


@app.post("/api/reset")
def post_reset():
    state["engine"].reset()
    return state["engine"].state()


@app.post("/api/nodes/{idx}/toggle")
def toggle_node(idx: int):
    if not 0 <= idx < len(state["engine"].nodes):
        raise HTTPException(status_code=404, detail="No such node.")
    state["engine"].toggle_node(idx)
    return state["engine"].state()


@app.get("/api/toy/rsa")
def toy_rsa(p: int = 61, q: int = 53, m: int = 65, e: int | None = None):
    return _guard(toy_math.toy_rsa, p, q, m, e)


@app.get("/api/toy/elgamal")
def toy_elgamal(p: int = 23, g: int = 5, x: int = 6, k: int = 3, m: int = 10):
    return _guard(toy_math.toy_elgamal, p, g, x, k, m)


@app.get("/api/benchmark")
def get_benchmark(include_2048: bool = Query(False)):
    return benchmark.run_benchmark(include_2048)
