"""Tests for Know Your Agent replay protection (kya/replay.py)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from kya import (
    ALL_CLASSES,
    ReplayStore,
    authorize_purchase,
    authorize_purchase_chain,
    build_corpus,
    delegate_credential,
    evaluate_corpus,
    generate_keypair,
    issue_credential,
    verify_credential,
)
from service.app import create_app


def make_credential(private_key, **overrides):
    now = datetime.now(timezone.utc)
    args = {
        "agent_id": "agent-shopper-01",
        "principal": "user-123",
        "scope": {"max_amount_usd": 50.0, "categories": ["electronics"]},
        "not_before": now - timedelta(minutes=5),
        "not_after": now + timedelta(hours=1),
    }
    args.update(overrides)
    return issue_credential(private_key, **args)


def make_chain(private_key):
    now = datetime.now(timezone.utc)
    root = make_credential(private_key)
    child = delegate_credential(
        private_key,
        root,
        agent_id="agent-sub-01",
        scope={"max_amount_usd": 20.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=30),
    )
    return root, child


# -- the store itself -------------------------------------------------------


def test_check_and_record_first_true_second_false():
    store = ReplayStore()
    assert store.check_and_record("cred-1", "order-1") is True
    assert store.check_and_record("cred-1", "order-1") is False
    assert store.is_seen("cred-1", "order-1") is True
    assert len(store) == 1


def test_same_presentation_id_under_another_credential_is_new():
    store = ReplayStore()
    assert store.check_and_record("cred-1", "order-1") is True
    assert store.check_and_record("cred-2", "order-1") is True
    assert len(store) == 2


def test_replay_keeps_original_seen_at():
    store = ReplayStore()
    store.check_and_record("cred-1", "order-1", seen_at="2026-11-19T08:00:00Z")
    store.check_and_record("cred-1", "order-1", seen_at="2026-11-19T09:00:00Z")
    assert store.entries()[0]["seen_at"] == "2026-11-19T08:00:00Z"


def test_invalid_ids_raise():
    store = ReplayStore()
    with pytest.raises(ValueError):
        store.check_and_record("", "order-1")
    with pytest.raises(ValueError):
        store.check_and_record("cred-1", None)
    with pytest.raises(ValueError):
        store.check_and_record("cred-1", "order-1", seen_at="not-a-time")


def test_json_round_trip():
    store = ReplayStore()
    store.check_and_record("cred-1", "order-1", seen_at="2026-11-19T08:00:00Z")
    store.check_and_record("cred-2", "order-9", seen_at="2026-11-19T08:05:00Z")
    restored = ReplayStore.from_json(store.to_json())
    assert restored.entries() == store.entries()
    assert restored.is_seen("cred-1", "order-1") is True


def test_from_json_rejects_bad_version_duplicates_and_dup_keys():
    with pytest.raises(ValueError):
        ReplayStore.from_json('{"version": 2, "entries": []}')
    with pytest.raises(ValueError):
        ReplayStore.from_json('{"version": true, "entries": []}')
    with pytest.raises(ValueError):
        ReplayStore.from_json(
            '{"version": 1, "entries": ['
            '{"credential_id": "c", "presentation_id": "p"},'
            '{"credential_id": "c", "presentation_id": "p"}]}'
        )
    with pytest.raises(ValueError):
        ReplayStore.from_json('{"version": 1, "version": 1, "entries": []}')
    with pytest.raises(ValueError):
        ReplayStore.from_json("not json")


def test_prune_drops_only_entries_before_cutoff():
    store = ReplayStore()
    store.check_and_record("cred-1", "order-1", seen_at="2026-11-19T08:00:00Z")
    store.check_and_record("cred-1", "order-2", seen_at="2026-11-19T10:00:00Z")
    assert store.prune(seen_before="2026-11-19T09:00:00Z") == 1
    assert store.is_seen("cred-1", "order-1") is False
    assert store.is_seen("cred-1", "order-2") is True


# -- purchase authorization ---------------------------------------------------


def test_first_spend_allowed_replay_rejected():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    store = ReplayStore()
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (True, "allowed")
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (False, "replay")


def test_fresh_presentation_id_under_same_credential_allowed():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    store = ReplayStore()
    for presentation_id in ("order-1", "order-2"):
        ok, reason = authorize_purchase(
            public_key, credential, 30.0, "electronics",
            replay_store=store, presentation_id=presentation_id,
        )
        assert (ok, reason) == (True, "allowed")


def test_rejected_purchase_does_not_burn_presentation_id():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    store = ReplayStore()
    ok, reason = authorize_purchase(
        public_key, credential, 500.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (False, "amount_exceeds_scope")
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (True, "allowed")


def test_store_without_presentation_id_fails_closed():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=ReplayStore(),
    )
    assert (ok, reason) == (False, "missing_presentation_id")


def test_no_store_keeps_repeat_presentations_allowed():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    for _ in range(2):
        ok, reason = authorize_purchase(
            public_key, credential, 30.0, "electronics"
        )
        assert (ok, reason) == (True, "allowed")


def test_verify_alone_never_consumes_a_presentation():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    for _ in range(2):
        ok, reason = verify_credential(public_key, credential)
        assert (ok, reason) == (True, "ok")
    store = ReplayStore()
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (True, "allowed")


def test_chain_replay_keyed_by_leaf():
    private_key, public_key = generate_keypair()
    root, child = make_chain(private_key)
    store = ReplayStore()
    ok, reason = authorize_purchase_chain(
        public_key, [root, child], 15.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (True, "allowed")
    ok, reason = authorize_purchase_chain(
        public_key, [root, child], 15.0, "electronics",
        replay_store=store, presentation_id="order-1",
    )
    assert (ok, reason) == (False, "replay")
    assert store.is_seen(child["payload"]["credential_id"], "order-1")


# -- gate evaluation ------------------------------------------------------------


def test_evaluate_with_replay_protection_catches_in_window_replays():
    corpus = build_corpus(99, counts={cls: 4 for cls in ALL_CLASSES})
    result = evaluate_corpus(corpus, replay_protection=True)
    assert result["missed_attack_ids"] == []
    replay = result["by_class"]["attack_replay_in_window"]
    assert replay["correct_rate"] == 1.0
    assert replay["reasons"] == {"replay": 4}
    # No other verdict moves: 8 legitimate and 12 policy transactions
    # behave exactly as they do without protection.
    assert result["by_family"]["legitimate"]["accepted"] == 8
    assert result["by_family"]["policy"]["rejected"] == 12
    assert result["n_correct"] == 80


def test_evaluate_default_corpus_with_replay_protection():
    result = evaluate_corpus(build_corpus(), replay_protection=True)
    attack = result["by_family"]["attack"]
    assert attack["missed"] == 0
    assert attack["correct"] == attack["n"] == 1950
    assert result["false_reject_ids"] == []


# -- the demo service -----------------------------------------------------------


def test_service_checkout_replay_and_fresh_id():
    private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    credential = make_credential(private_key)
    body = {
        "credential": credential,
        "amount_usd": 30.0,
        "category": "electronics",
        "presentation_id": "order-1",
    }
    response = client.post("/checkout", json=body)
    assert response.json() == {"accepted": True, "reason": "allowed"}
    response = client.post("/checkout", json=body)
    assert response.json() == {"accepted": False, "reason": "replay"}
    body["presentation_id"] = "order-2"
    response = client.post("/checkout", json=body)
    assert response.json() == {"accepted": True, "reason": "allowed"}


def test_service_checkout_without_presentation_id_unchanged():
    private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    credential = make_credential(private_key)
    body = {
        "credential": credential,
        "amount_usd": 30.0,
        "category": "electronics",
    }
    for _ in range(2):
        response = client.post("/checkout", json=body)
        assert response.json() == {"accepted": True, "reason": "allowed"}


def test_service_replay_state_is_per_app_unless_shared():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    body = {
        "credential": credential,
        "amount_usd": 30.0,
        "category": "electronics",
        "presentation_id": "order-1",
    }
    first = TestClient(create_app(public_key))
    assert first.post("/checkout", json=body).json()["accepted"] is True
    second = TestClient(create_app(public_key))
    assert second.post("/checkout", json=body).json()["accepted"] is True
    shared = ReplayStore()
    third = TestClient(create_app(public_key, replay_store=shared))
    fourth = TestClient(create_app(public_key, replay_store=shared))
    assert third.post("/checkout", json=body).json()["accepted"] is True
    assert fourth.post("/checkout", json=body).json() == {
        "accepted": False,
        "reason": "replay",
    }


def test_service_evaluate_replay_protection_flag():
    _private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    counts = {cls: 2 for cls in ALL_CLASSES}
    response = client.post(
        "/evaluate", json={"seed": 99, "counts": counts}
    )
    assert response.json()["by_family"]["attack"]["missed"] == 2
    response = client.post(
        "/evaluate",
        json={"seed": 99, "counts": counts, "replay_protection": True},
    )
    assert response.json()["by_family"]["attack"]["missed"] == 0
