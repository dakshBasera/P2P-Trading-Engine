import pytest

from app import crypto_elgamal as eg
from app import crypto_rsa as rsa
from app import toy_math
from app.engine import ATTACKS, Engine


@pytest.fixture(scope="module")
def engine():
    return Engine()


@pytest.fixture(autouse=True)
def fresh(engine):
    engine.reset()


def test_rsa_sign_verify_and_tamper():
    key = rsa.generate_keypair(1024)
    sig = rsa.sign(b"10 kWh", key)
    assert rsa.verify(b"10 kWh", sig, key.public())
    assert not rsa.verify(b"11 kWh", sig, key.public())
    other = rsa.generate_keypair(1024)
    assert not rsa.verify(b"10 kWh", sig, other.public())


def test_elgamal_roundtrip_multi_block():
    key = eg.generate_keypair(eg.get_group(512))
    data = bytes(range(256)) * 2
    ct = eg.encrypt(key.public(), data)
    assert len(ct["chunks"]) > 1
    assert eg.decrypt(key, ct) == data


def test_elgamal_is_randomised():
    key = eg.generate_keypair(eg.get_group(512))
    assert eg.encrypt(key.public(), b"same") != eg.encrypt(key.public(), b"same")


def test_honest_trade_settles_on_all_nodes(engine):
    res = engine.honest("asha", "meera", 5.0, 6.5)
    assert res["accepted"]
    assert [s["status"] for s in res["steps"]] == ["pass"] * 6
    state = engine.state()
    people = {p["id"]: p for p in state["participants"]}
    assert people["asha"]["ledger_kwh"] == 37.0
    assert people["meera"]["ledger_kwh"] == 8.0
    assert people["meera"]["credit"] == 1500 - 32.5
    assert all(n["height"] == 1 and n["valid"] for n in state["nodes"])


@pytest.mark.parametrize("kind", list(ATTACKS))
def test_every_attack_is_rejected(engine, kind):
    res = engine.attack(kind, "asha", "meera", 2.0, 6.5)
    assert not res["accepted"]
    if kind == "replay":
        assert res["preface"]["accepted"]
    else:
        assert engine.state()["nodes"][0]["height"] == 0


def test_replay_fails_on_nonce(engine):
    res = engine.attack("replay", "asha", "meera", 2.0, 6.5)
    failing = [s for s in res["steps"] if s["status"] == "fail"][0]
    assert failing["id"] == "fresh"


def test_forged_signature_is_caught_by_rsa_step(engine):
    res = engine.attack("forge", "asha", "meera", 2.0, 6.5)
    failing = [s for s in res["steps"] if s["status"] == "fail"][0]
    assert failing["id"] == "signature"


def test_overclaim_is_caught_by_energy_step(engine):
    res = engine.attack("overclaim", "asha", "meera", 2.0, 6.5)
    failing = [s for s in res["steps"] if s["status"] == "fail"][0]
    assert failing["id"] == "energy"


def test_one_faulty_node_cannot_change_outcome(engine):
    engine.toggle_node(1)
    assert engine.honest("ravi", "meera", 1.0, 6.0)["accepted"]
    assert not engine.attack("forge", "asha", "meera", 1.0, 6.0)["accepted"]


def test_two_faulty_nodes_break_liveness(engine):
    engine.toggle_node(1)
    engine.toggle_node(2)
    assert not engine.honest("ravi", "meera", 1.0, 6.0)["accepted"]


def test_toy_rsa_textbook_values():
    out = toy_math.toy_rsa(61, 53, 65, 17)
    assert out["ok"] and out["private"]["d"] == 2753
    assert out["euler"]["value"] == 1


def test_toy_elgamal_and_bad_root():
    assert toy_math.toy_elgamal(23, 5, 6, 3, 10)["ok"]
    with pytest.raises(ValueError):
        toy_math.toy_elgamal(23, 4, 6, 3, 10)
