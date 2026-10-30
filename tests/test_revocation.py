"""Tests for Know Your Agent revocation management (kya/revocation.py)."""

from datetime import datetime, timedelta, timezone

import pytest

from kya import (
    RevocationList,
    authorize_purchase,
    authorize_purchase_chain,
    delegate_credential,
    generate_keypair,
    issue_credential,
    verify_chain,
    verify_credential,
)


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


def test_revoke_then_is_revoked():
    store = RevocationList()
    assert store.is_revoked("cred-1") is False
    assert store.revoke("cred-1", reason="reported stolen") is True
    assert store.is_revoked("cred-1") is True
    assert "cred-1" in store
    assert len(store) == 1


def test_revoke_is_idempotent_and_keeps_original_entry():
    store = RevocationList()
    first_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
    assert store.revoke("cred-1", reason="first", revoked_at=first_time) is True
    assert store.revoke("cred-1", reason="second") is False
    assert len(store) == 1
    entry = store.get("cred-1")
    assert entry["reason"] == "first"
    assert entry["revoked_at"] == "2026-10-30T12:00:00Z"


def test_revoke_rejects_bad_ids_reasons_and_times():
    store = RevocationList()
    for bad_id in ("", None, 123):
        with pytest.raises(ValueError):
            store.revoke(bad_id)
    with pytest.raises(ValueError):
        store.revoke("cred-1", reason=123)
    with pytest.raises(ValueError):
        store.revoke("cred-1", revoked_at="not-a-time")
    assert len(store) == 0


def test_revoke_credential_extracts_id_and_rejects_malformed():
    private_key, _ = generate_keypair()
    store = RevocationList()
    credential = make_credential(private_key)
    credential_id = credential["payload"]["credential_id"]
    assert store.revoke_credential(credential, reason="agent decommissioned") is True
    assert store.is_revoked(credential_id) is True
    assert store.get(credential_id)["reason"] == "agent decommissioned"
    for bad in (None, {}, {"payload": {}}, {"payload": {"credential_id": ""}}):
        with pytest.raises(ValueError):
            store.revoke_credential(bad)


def test_revoked_credential_fails_inside_window_via_store():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    store = RevocationList()
    assert verify_credential(public_key, credential, revoked_ids=store) == (True, "ok")
    store.revoke_credential(credential)
    assert verify_credential(public_key, credential, revoked_ids=store) == (
        False,
        "revoked",
    )


def test_revoked_credential_fails_via_plain_set_and_store_ids():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    store = RevocationList()
    store.revoke_credential(credential)
    # Backward compat: a plain set still works.
    assert verify_credential(
        public_key, credential, revoked_ids=store.revoked_ids()
    ) == (False, "revoked")
    # The returned set is a copy: mutating it must not unrevoke anything.
    ids = store.revoked_ids()
    ids.clear()
    assert store.is_revoked(credential["payload"]["credential_id"]) is True
    assert verify_credential(public_key, credential, revoked_ids=store) == (
        False,
        "revoked",
    )


def test_revoked_beats_expired_in_check_order():
    private_key, public_key = generate_keypair()
    now = datetime.now(timezone.utc)
    credential = make_credential(
        private_key,
        not_before=now - timedelta(hours=2),
        not_after=now - timedelta(hours=1),
    )
    assert verify_credential(public_key, credential) == (False, "expired")
    store = RevocationList()
    store.revoke_credential(credential)
    assert verify_credential(public_key, credential, revoked_ids=store) == (
        False,
        "revoked",
    )


def test_revoked_root_or_leaf_fails_whole_chain():
    private_key, public_key = generate_keypair()
    root, child = make_chain(private_key)
    store = RevocationList()
    assert verify_chain(public_key, [root, child], revoked_ids=store) == (True, "ok")

    store.revoke_credential(child)
    assert verify_chain(public_key, [root, child], revoked_ids=store) == (
        False,
        "revoked",
    )

    store = RevocationList()
    store.revoke_credential(root)
    assert verify_chain(public_key, [root, child], revoked_ids=store) == (
        False,
        "revoked",
    )


def test_authorize_purchase_and_chain_honor_revocation():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    root, child = make_chain(private_key)
    store = RevocationList()
    assert authorize_purchase(
        public_key, credential, 30.0, "electronics", revoked_ids=store
    ) == (True, "allowed")
    assert authorize_purchase_chain(
        public_key, [root, child], 15.0, "electronics", revoked_ids=store
    ) == (True, "allowed")

    store.revoke_credential(credential)
    assert authorize_purchase(
        public_key, credential, 30.0, "electronics", revoked_ids=store
    ) == (False, "revoked")

    store = RevocationList()
    store.revoke_credential(child)
    assert authorize_purchase_chain(
        public_key, [root, child], 15.0, "electronics", revoked_ids=store
    ) == (False, "revoked")


def test_entries_are_copies_in_revocation_order():
    store = RevocationList()
    store.revoke("cred-a", reason="one")
    store.revoke("cred-b")
    entries = store.entries()
    assert [entry["credential_id"] for entry in entries] == ["cred-a", "cred-b"]
    assert entries[0]["reason"] == "one"
    assert entries[1]["reason"] is None
    entries[0]["reason"] = "tampered"
    assert store.get("cred-a")["reason"] == "one"


def test_dict_and_json_round_trips_preserve_entries():
    store = RevocationList()
    store.revoke("cred-a", reason="reported stolen")
    store.revoke("cred-b", revoked_at="2026-10-30T12:00:00Z")
    restored = RevocationList.from_dict(store.to_dict())
    assert restored.entries() == store.entries()
    assert restored.revoked_ids() == {"cred-a", "cred-b"}

    from_json = RevocationList.from_json(store.to_json())
    assert from_json.entries() == store.entries()

    # A list loaded from disk still revokes at verification time.
    private_key, public_key = generate_keypair()
    credential = make_credential(
        private_key, credential_id="cred-a"
    )
    assert verify_credential(public_key, credential, revoked_ids=from_json) == (
        False,
        "revoked",
    )


def test_from_dict_rejects_malformed_data():
    with pytest.raises(ValueError):
        RevocationList.from_dict(None)
    with pytest.raises(ValueError):
        RevocationList.from_dict({"version": 99, "entries": []})
    with pytest.raises(ValueError):
        RevocationList.from_dict({"version": 1, "entries": "not-a-list"})
    with pytest.raises(ValueError):
        RevocationList.from_dict(
            {"version": 1, "entries": [{"credential_id": "x"}, {"credential_id": "x"}]}
        )
    with pytest.raises(ValueError):
        RevocationList.from_dict(
            {"version": 1, "entries": [{"credential_id": ""}]}
        )
    with pytest.raises(ValueError):
        RevocationList.from_dict(
            {"version": 1, "entries": [{"credential_id": "x", "reason": 5}]}
        )
    with pytest.raises(ValueError):
        RevocationList.from_json("{not json")


def test_constructor_preloads_entries_and_rejects_duplicates():
    store = RevocationList(
        [
            {"credential_id": "cred-a", "revoked_at": "2026-10-30T12:00:00Z"},
            {"credential_id": "cred-b"},
        ]
    )
    assert len(store) == 2
    assert store.is_revoked("cred-a") is True
    with pytest.raises(ValueError):
        RevocationList(
            [{"credential_id": "cred-a"}, {"credential_id": "cred-a"}]
        )


def test_revoked_at_normalizes_datetime_to_utc_z():
    store = RevocationList()
    store.revoke(
        "cred-a",
        revoked_at=datetime(2026, 10, 30, 14, 30, 0, tzinfo=timezone.utc),
    )
    assert store.get("cred-a")["revoked_at"] == "2026-10-30T14:30:00Z"
