"""Tests for the seeded evaluation corpus (kya/corpus.py)."""

from datetime import datetime, timezone

import pytest

from kya import (
    ALL_CLASSES,
    ATTACK_CLASSES,
    LEGIT_CLASSES,
    POLICY_CLASSES,
    authorize_purchase,
    authorize_purchase_chain,
    build_corpus,
    corpus_to_json,
    load_public_key_pem,
)
from kya.corpus import DEFAULT_COUNTS

TINY_COUNTS = {cls: 4 for cls in ALL_CLASSES}


def tiny_corpus(seed=99):
    return build_corpus(seed, counts=TINY_COUNTS)


def gate_verdicts(corpus):
    """Run the gate over a corpus, returning {tx_id: (ok, reason)}."""
    public_key = load_public_key_pem(corpus["issuer_public_key_pem"])
    revoked = set(corpus["revoked_ids"])
    verdicts = {}
    for tx in corpus["transactions"]:
        now = datetime.fromisoformat(tx["timestamp"].replace("Z", "+00:00"))
        if tx["kind"] == "single":
            verdict = authorize_purchase(
                public_key,
                tx["credential"],
                tx["amount_usd"],
                tx["category"],
                now=now,
                revoked_ids=revoked,
            )
        else:
            verdict = authorize_purchase_chain(
                public_key,
                tx["chain"],
                tx["amount_usd"],
                tx["category"],
                now=now,
                revoked_ids=revoked,
            )
        verdicts[tx["tx_id"]] = verdict
    return verdicts


def test_corpus_is_deterministic():
    first = corpus_to_json(tiny_corpus())
    second = corpus_to_json(tiny_corpus())
    assert first == second


def test_corpus_seed_changes_output():
    assert corpus_to_json(tiny_corpus(1)) != corpus_to_json(tiny_corpus(2))


def test_corpus_shape_and_counts():
    corpus = tiny_corpus()
    assert corpus["seed"] == 99
    assert len(corpus["transactions"]) == sum(TINY_COUNTS.values())
    seen = {}
    for tx in corpus["transactions"]:
        seen[tx["cls"]] = seen.get(tx["cls"], 0) + 1
        assert tx["tx_id"].startswith("tx-")
    assert seen == TINY_COUNTS
    # Stream order: timestamps never decrease.
    stamps = [tx["timestamp"] for tx in corpus["transactions"]]
    assert stamps == sorted(stamps)


def test_corpus_labels_match_families():
    corpus = tiny_corpus()
    for tx in corpus["transactions"]:
        if tx["cls"] in LEGIT_CLASSES:
            assert tx["label"] == 0
        elif tx["cls"] in POLICY_CLASSES:
            assert tx["label"] is None
        else:
            assert tx["cls"] in ATTACK_CLASSES
            assert tx["label"] == 1


def test_unknown_class_count_rejected():
    with pytest.raises(ValueError):
        build_corpus(1, counts={"no_such_class": 1})


def test_default_counts_total_about_five_thousand():
    total = sum(DEFAULT_COUNTS.values())
    assert 4800 <= total <= 5200
    assert len(ATTACK_CLASSES) >= 10


def test_gate_accepts_all_legitimate_traffic():
    corpus = tiny_corpus()
    verdicts = gate_verdicts(corpus)
    for tx in corpus["transactions"]:
        if tx["cls"] in LEGIT_CLASSES:
            assert verdicts[tx["tx_id"]] == (True, "allowed"), tx["cls"]


def test_gate_rejects_policy_violations_with_policy_reasons():
    corpus = tiny_corpus()
    verdicts = gate_verdicts(corpus)
    for tx in corpus["transactions"]:
        if tx["cls"] in (
            "policy_over_limit",
            "policy_chain_over_limit",
        ):
            assert verdicts[tx["tx_id"]] == (False, "amount_exceeds_scope")
        elif tx["cls"] == "policy_wrong_category":
            assert verdicts[tx["tx_id"]] == (False, "category_not_allowed")


def test_gate_attack_reasons():
    corpus = tiny_corpus()
    verdicts = gate_verdicts(corpus)
    expected = {
        "attack_forged_signature": "bad_signature",
        "attack_tampered_scope": "bad_signature",
        "attack_tampered_identity": "bad_signature",
        "attack_tampered_window": "bad_signature",
        "attack_expired": "expired",
        "attack_not_yet_valid": "not_yet_valid",
        "attack_revoked_single": "revoked",
        "attack_replay_after_window": "expired",
        "attack_chain_scope_widened": "scope_widened",
        "attack_chain_window_widened": "window_widened",
        "attack_chain_broken_linkage": "bad_chain",
        "attack_chain_principal_mismatch": "principal_mismatch",
        "attack_chain_revoked": "revoked",
    }
    for tx in corpus["transactions"]:
        if tx["cls"] in expected:
            ok, reason = verdicts[tx["tx_id"]]
            assert not ok, tx["cls"]
            assert reason == expected[tx["cls"]], (
                tx["cls"],
                tx["meta"],
                reason,
            )
        elif tx["cls"] == "attack_malformed":
            ok, reason = verdicts[tx["tx_id"]]
            assert not ok
            assert reason in ("malformed", "unsupported_algorithm")


def test_count_values_must_be_non_negative_ints():
    for bad in (-1, 1.5, "4", True, None):
        with pytest.raises(ValueError):
            build_corpus(1, counts={"legit_single": bad})


def test_zero_count_drops_a_class():
    corpus = build_corpus(7, counts={"legit_single": 3, "legit_chain": 0})
    classes = {tx["cls"] for tx in corpus["transactions"]}
    assert "legit_chain" not in classes
    assert corpus["counts"]["legit_chain"] == 0
    assert corpus["counts"]["legit_single"] == 3


def test_corpus_carries_revocation_state_for_revoked_classes():
    corpus = tiny_corpus()
    revoked = set(corpus["revoked_ids"])
    assert revoked
    assert set(corpus["revoked_at"]) == revoked
    revoked_classes = {"attack_revoked_single", "attack_chain_revoked"}
    for tx in corpus["transactions"]:
        if tx["cls"] in revoked_classes:
            presented = []
            if tx["credential"] is not None:
                presented.append(tx["credential"]["payload"]["credential_id"])
            for link in tx["chain"] or []:
                presented.append(link["payload"]["credential_id"])
            # Exactly the presented credential, or one link of the
            # presented chain, is in the corpus revocation state.
            assert any(cid in revoked for cid in presented), tx["cls"]
    # Every revoked id was issued inside this corpus, never invented.
    issued = set()
    for tx in corpus["transactions"]:
        presented = [tx["credential"]] + list(tx["chain"] or [])
        for cred in presented:
            if isinstance(cred, dict) and isinstance(cred.get("payload"), dict):
                cid = cred["payload"].get("credential_id")
                if isinstance(cid, str):
                    issued.add(cid)
    assert revoked <= issued


def test_replay_in_window_is_accepted_known_limitation():
    # KYA v0.1 has no nonce: an in-window replay of a genuine,
    # in-scope presentation passes the gate. The corpus measures
    # this limitation instead of hiding it.
    corpus = tiny_corpus()
    verdicts = gate_verdicts(corpus)
    for tx in corpus["transactions"]:
        if tx["cls"] == "attack_replay_in_window":
            assert verdicts[tx["tx_id"]] == (True, "allowed")
            assert tx["meta"]["source_tx_id"].startswith("tx-")
