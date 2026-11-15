"""Tests for the gate evaluation helper (kya/evaluate.py)."""

import copy

import pytest

from kya import (
    ALL_CLASSES,
    ATTACK_CLASSES,
    RevocationList,
    build_corpus,
    evaluate_corpus,
    evaluation_from_json,
    evaluation_to_json,
    generate_keypair,
    load_public_key_pem,
)

TINY_COUNTS = {cls: 4 for cls in ALL_CLASSES}


def tiny_corpus(seed=99):
    return build_corpus(seed, counts=TINY_COUNTS)


def test_tiny_corpus_headline_numbers():
    result = evaluate_corpus(tiny_corpus())
    assert result["seed"] == 99
    assert result["n_transactions"] == 80
    # 8 legitimate accepted, everything else rejected except the 4
    # in-window replays.
    assert result["n_accepted"] == 12
    assert result["n_rejected"] == 68
    assert result["n_correct"] == 76
    assert result["correct_rate"] == pytest.approx(0.95)


def test_family_breakdown():
    result = evaluate_corpus(tiny_corpus())
    legit = result["by_family"]["legitimate"]
    assert legit == {
        "n": 8,
        "accepted": 8,
        "rejected": 0,
        "correct": 8,
        "correct_rate": 1.0,
    }
    policy = result["by_family"]["policy"]
    assert policy["n"] == 12
    assert policy["accepted"] == 0
    assert policy["correct_rate"] == 1.0
    attack = result["by_family"]["attack"]
    assert attack["n"] == 60
    assert attack["accepted"] == 4
    assert attack["missed"] == 4
    assert attack["catch_rate"] == pytest.approx(56 / 60)


def test_per_class_rates_and_reasons():
    result = evaluate_corpus(tiny_corpus())
    assert set(result["by_class"]) == set(ALL_CLASSES)
    for cls in ATTACK_CLASSES:
        bucket = result["by_class"][cls]
        assert bucket["family"] == "attack"
        assert "catch_rate" in bucket
    replay = result["by_class"]["attack_replay_in_window"]
    assert replay["correct_rate"] == 0.0
    assert replay["catch_rate"] == 0.0
    assert replay["missed"] == 4
    assert replay["reasons"] == {"allowed": 4}
    forged = result["by_class"]["attack_forged_signature"]
    assert forged["correct_rate"] == 1.0
    assert forged["reasons"] == {"bad_signature": 4}
    over_limit = result["by_class"]["policy_over_limit"]
    assert over_limit["reasons"] == {"amount_exceeds_scope": 4}
    assert "catch_rate" not in over_limit


def test_verdicts_match_corpus_order_and_gate_reasons():
    corpus = tiny_corpus()
    result = evaluate_corpus(corpus)
    assert [v["tx_id"] for v in result["verdicts"]] == [
        tx["tx_id"] for tx in corpus["transactions"]
    ]
    expected = {
        "attack_expired": "expired",
        "attack_revoked_single": "revoked",
        "attack_chain_scope_widened": "scope_widened",
        "attack_chain_principal_mismatch": "principal_mismatch",
        "legit_chain": "allowed",
    }
    for verdict in result["verdicts"]:
        if verdict["cls"] in expected:
            assert verdict["reason"] == expected[verdict["cls"]]
    assert sum(result["by_reason"].values()) == result["n_transactions"]


def test_missed_and_false_reject_ids():
    corpus = tiny_corpus()
    result = evaluate_corpus(corpus)
    replay_ids = [
        tx["tx_id"]
        for tx in corpus["transactions"]
        if tx["cls"] == "attack_replay_in_window"
    ]
    assert result["missed_attack_ids"] == replay_ids
    assert result["false_reject_ids"] == []


def test_evaluation_is_deterministic_and_json_round_trips():
    corpus = tiny_corpus()
    first = evaluate_corpus(corpus)
    second = evaluate_corpus(corpus)
    assert first == second
    restored = evaluation_from_json(evaluation_to_json(first))
    assert restored == first


def test_evaluation_from_json_rejects_bad_input():
    with pytest.raises(ValueError):
        evaluation_from_json("not json")
    with pytest.raises(ValueError):
        evaluation_from_json('{"version": 99}')
    result = evaluate_corpus(tiny_corpus())
    broken = dict(result, n_accepted="12")
    with pytest.raises(ValueError):
        evaluation_from_json(evaluation_to_json(broken))


def test_default_corpus_headline():
    result = evaluate_corpus(build_corpus())
    assert result["n_transactions"] == 5100
    legit = result["by_family"]["legitimate"]
    assert legit["n"] == 2500 and legit["correct_rate"] == 1.0
    assert result["by_family"]["policy"]["correct_rate"] == 1.0
    attack = result["by_family"]["attack"]
    assert attack["n"] == 1950
    # The only misses at the default seed are the 100 in-window
    # replays, the known v0.1 limitation with no nonce.
    assert attack["missed"] == 100
    assert result["by_class"]["attack_replay_in_window"]["missed"] == 100
    assert len(result["missed_attack_ids"]) == 100


def test_caller_public_key_overrides_corpus_key():
    corpus = tiny_corpus()
    key = load_public_key_pem(corpus["issuer_public_key_pem"])
    assert evaluate_corpus(corpus, public_key=key) == evaluate_corpus(corpus)
    _, wrong_key = generate_keypair()
    result = evaluate_corpus(corpus, public_key=wrong_key)
    # Nothing verifies under the wrong key, so legitimate traffic is
    # falsely rejected and no purchase is ever allowed.
    assert result["n_accepted"] == 0
    assert result["false_reject_ids"] == [
        tx["tx_id"]
        for tx in corpus["transactions"]
        if tx["cls"] in ("legit_single", "legit_chain")
    ]


def test_revocation_override_measures_what_revocation_is_worth():
    corpus = tiny_corpus()
    result = evaluate_corpus(corpus, revoked_ids=set())
    # Without the corpus revocation state, revoked singles and the
    # leaf and middle revocations in chains verify and are bought.
    # Root-revoked chains still fail at the purchase step only if the
    # leaf scope rejects; the revoked classes lose their clean sweep.
    assert result["by_class"]["attack_revoked_single"]["correct_rate"] == 0.0
    assert result["by_class"]["attack_revoked_single"]["missed"] == 4
    assert result["by_class"]["attack_chain_revoked"]["missed"] >= 1
    assert result["correct_rate"] < 0.95


def test_revocation_list_accepted_as_revoked_ids():
    corpus = tiny_corpus()
    revocations = RevocationList()
    for credential_id in corpus["revoked_ids"]:
        revocations.revoke(credential_id)
    assert evaluate_corpus(corpus, revoked_ids=revocations) == evaluate_corpus(
        corpus
    )


def test_empty_corpus_has_undefined_rates_not_zeroes():
    corpus = build_corpus(5, counts={cls: 0 for cls in ALL_CLASSES})
    result = evaluate_corpus(corpus)
    assert result["n_transactions"] == 0
    assert result["correct_rate"] is None
    assert result["by_family"] == {}
    assert result["by_class"] == {}
    assert result["verdicts"] == []


def test_unknown_class_groups_by_label():
    corpus = tiny_corpus()
    source = next(
        tx for tx in corpus["transactions"] if tx["cls"] == "legit_single"
    )
    tx = copy.deepcopy(source)
    # A genuine legitimate presentation, relabeled as a future attack
    # class this module predates.
    tx["cls"] = "attack_future_class"
    tx["label"] = 1
    tx["tx_id"] = "tx-future-1"
    single = {
        "seed": corpus["seed"],
        "issuer_public_key_pem": corpus["issuer_public_key_pem"],
        "revoked_ids": corpus["revoked_ids"],
        "transactions": [tx],
    }
    result = evaluate_corpus(single)
    bucket = result["by_class"]["attack_future_class"]
    assert bucket["family"] == "attack"
    # The gate accepted it, and as an attack that is a miss.
    assert bucket["missed"] == 1
    assert result["missed_attack_ids"] == ["tx-future-1"]


def test_malformed_corpus_inputs_raise():
    with pytest.raises(ValueError):
        evaluate_corpus("not a corpus")
    with pytest.raises(ValueError):
        evaluate_corpus({"transactions": "not a list"})
    with pytest.raises(ValueError):
        evaluate_corpus({"transactions": []})
    corpus = tiny_corpus()
    no_key = dict(corpus, issuer_public_key_pem=None)
    with pytest.raises(ValueError):
        evaluate_corpus(no_key)


def test_malformed_transactions_raise():
    corpus = tiny_corpus()
    base = corpus["transactions"][0]

    def one(tx):
        return evaluate_corpus(dict(corpus, transactions=[tx]))

    with pytest.raises(ValueError):
        one(dict(base, tx_id=""))
    with pytest.raises(ValueError):
        one(dict(base, kind="sideways"))
    with pytest.raises(ValueError):
        one(dict(base, timestamp="not a time"))
    with pytest.raises(ValueError):
        one(dict(base, label=7))
    duplicate = evaluate_corpus
    with pytest.raises(ValueError):
        duplicate(dict(corpus, transactions=[base, base]))


def test_subset_corpus_evaluates_only_what_it_holds():
    counts = {cls: 0 for cls in ALL_CLASSES}
    counts.update({"legit_single": 3, "attack_expired": 2})
    corpus = build_corpus(7, counts=counts)
    result = evaluate_corpus(corpus)
    assert result["n_transactions"] == 5
    assert result["correct_rate"] == 1.0
    assert set(result["by_class"]) == {"legit_single", "attack_expired"}
