"""Tests for shared, persistent state (kya/shared.py)."""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from kya import (
    FileReplayStore,
    FileRevocationList,
    ReplayStore,
    RevocationList,
    authorize_purchase,
    generate_keypair,
    issue_credential,
    verify_credential,
)
from service.app import create_app


def make_credential(private_key):
    now = datetime.now(timezone.utc)
    return issue_credential(
        private_key,
        agent_id="agent-shopper-01",
        principal="user-123",
        scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )


# -- file revocations -------------------------------------------------------


def test_revocation_visible_to_second_instance(tmp_path):
    path = str(tmp_path / "revocations.json")
    first = FileRevocationList(path)
    assert first.revoke("cred-1", reason="reported stolen") is True
    second = FileRevocationList(path)
    assert second.is_revoked("cred-1") is True
    assert second.get("cred-1")["reason"] == "reported stolen"
    assert second.revoked_ids() == {"cred-1"}


def test_revocation_visible_without_recreating_instance(tmp_path):
    path = str(tmp_path / "revocations.json")
    first = FileRevocationList(path)
    second = FileRevocationList(path)
    first.revoke("cred-1")
    # The second instance was created before the revoke; a fresh read
    # must still see it, which is the whole point of shared state.
    assert second.is_revoked("cred-1") is True
    assert len(second) == 1


def test_revocation_survives_restart_and_matches_memory_format(tmp_path):
    path = str(tmp_path / "revocations.json")
    store = FileRevocationList(path)
    store.revoke("cred-1", revoked_at="2026-11-21T08:00:00Z")
    with open(path, encoding="utf-8") as handle:
        on_disk = handle.read()
    # The file is exactly the in-memory store format.
    assert RevocationList.from_json(on_disk).revoked_ids() == {"cred-1"}
    assert FileRevocationList(path).entries() == store.entries()


def test_double_revoke_across_instances_keeps_first_entry(tmp_path):
    path = str(tmp_path / "revocations.json")
    first = FileRevocationList(path)
    second = FileRevocationList(path)
    assert first.revoke("cred-1", reason="first") is True
    assert second.revoke("cred-1", reason="second") is False
    assert FileRevocationList(path).get("cred-1")["reason"] == "first"


def test_missing_file_starts_empty_and_is_created_on_first_revoke(tmp_path):
    path = str(tmp_path / "revocations.json")
    store = FileRevocationList(path)
    assert len(store) == 0
    assert store.is_revoked("cred-1") is False
    store.revoke("cred-1")
    assert os.path.exists(path)


def test_corrupt_revocation_file_fails_closed(tmp_path):
    path = tmp_path / "revocations.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError):
        FileRevocationList(str(path))
    path.write_text('{"version": 99, "entries": []}', encoding="utf-8")
    with pytest.raises(ValueError):
        FileRevocationList(str(path))


def test_revocation_file_preseeded_from_memory_store(tmp_path):
    memory = RevocationList()
    memory.revoke("cred-9", reason="seeded")
    path = tmp_path / "revocations.json"
    path.write_text(memory.to_json(), encoding="utf-8")
    assert FileRevocationList(str(path)).is_revoked("cred-9") is True


def test_file_revocation_blocks_verification_across_instances(tmp_path):
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    path = str(tmp_path / "revocations.json")
    writer = FileRevocationList(path)
    reader = FileRevocationList(path)
    ok, reason = verify_credential(public_key, credential, revoked_ids=reader)
    assert (ok, reason) == (True, "ok")
    writer.revoke_credential(credential)
    ok, reason = verify_credential(public_key, credential, revoked_ids=reader)
    assert (ok, reason) == (False, "revoked")


def test_invalid_path_raises():
    with pytest.raises(ValueError):
        FileRevocationList("")
    with pytest.raises(ValueError):
        FileReplayStore(None)


# -- file replay store --------------------------------------------------------


def test_replay_visible_to_second_instance(tmp_path):
    path = str(tmp_path / "replay.json")
    first = FileReplayStore(path)
    assert first.check_and_record("cred-1", "order-1") is True
    second = FileReplayStore(path)
    assert second.is_seen("cred-1", "order-1") is True
    assert second.check_and_record("cred-1", "order-1") is False


def test_replay_survives_restart_and_matches_memory_format(tmp_path):
    path = str(tmp_path / "replay.json")
    store = FileReplayStore(path)
    store.check_and_record("cred-1", "order-1", seen_at="2026-11-21T08:00:00Z")
    with open(path, encoding="utf-8") as handle:
        on_disk = handle.read()
    assert ReplayStore.from_json(on_disk).is_seen("cred-1", "order-1") is True
    assert FileReplayStore(path).entries() == store.entries()


def test_replay_authorize_blocks_cross_instance_replay(tmp_path):
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    path = str(tmp_path / "replay.json")
    first = FileReplayStore(path)
    second = FileReplayStore(path)
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=first, presentation_id="order-1",
    )
    assert (ok, reason) == (True, "allowed")
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=second, presentation_id="order-1",
    )
    assert (ok, reason) == (False, "replay")


def test_corrupt_replay_file_fails_closed(tmp_path):
    path = tmp_path / "replay.json"
    path.write_text('{"version": 1, "entries": [{"credential_id": "c"}]}',
                     encoding="utf-8")
    with pytest.raises(ValueError):
        FileReplayStore(str(path))


def test_file_replay_prune_persists(tmp_path):
    path = str(tmp_path / "replay.json")
    store = FileReplayStore(path)
    store.check_and_record("cred-1", "old", seen_at="2026-11-21T08:00:00Z")
    store.check_and_record("cred-1", "new", seen_at="2026-11-21T10:00:00Z")
    assert store.prune(seen_before="2026-11-21T09:00:00Z") == 1
    restored = FileReplayStore(path)
    assert restored.is_seen("cred-1", "old") is False
    assert restored.is_seen("cred-1", "new") is True


def test_no_leftover_temp_files_after_writes(tmp_path):
    path = str(tmp_path / "replay.json")
    store = FileReplayStore(path)
    store.check_and_record("cred-1", "order-1")
    names = sorted(os.listdir(tmp_path))
    assert names == ["replay.json", "replay.json.lock"]


def test_concurrent_like_interleaving_loses_nothing(tmp_path):
    # Two instances alternating writes: each write reloads first, so
    # neither overwrites the other's entries with a stale snapshot.
    path = str(tmp_path / "revocations.json")
    first = FileRevocationList(path)
    second = FileRevocationList(path)
    first.revoke("cred-1")
    second.revoke("cred-2")
    first.revoke("cred-3")
    assert FileRevocationList(path).revoked_ids() == {"cred-1", "cred-2", "cred-3"}


# -- the demo service -----------------------------------------------------------


def test_service_two_apps_share_state_by_path(tmp_path):
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    rev_path = str(tmp_path / "revocations.json")
    replay_path = str(tmp_path / "replay.json")
    app_one = TestClient(create_app(
        public_key, revocations_path=rev_path, replay_store_path=replay_path))
    app_two = TestClient(create_app(
        public_key, revocations_path=rev_path, replay_store_path=replay_path))
    body = {
        "credential": credential, "amount_usd": 30.0,
        "category": "electronics", "presentation_id": "order-1",
    }
    assert app_one.post("/checkout", json=body).json() == {
        "accepted": True, "reason": "allowed"}
    # Replay spent in app one is a replay in app two.
    assert app_two.post("/checkout", json=body).json() == {
        "accepted": False, "reason": "replay"}
    # Revocation made in app one blocks verification in app two.
    cid = credential["payload"]["credential_id"]
    assert app_one.post(
        "/revoke", json={"credential_id": cid}).json()["revoked"] is True
    assert app_two.post("/verify", json={"credential": credential}).json() == {
        "ok": False, "reason": "revoked"}


def test_service_path_and_instance_cannot_be_combined(tmp_path):
    _private_key, public_key = generate_keypair()
    with pytest.raises(ValueError):
        create_app(public_key, revocations=RevocationList(),
                   revocations_path=str(tmp_path / "r.json"))
    with pytest.raises(ValueError):
        create_app(public_key, replay_store=ReplayStore(),
                   replay_store_path=str(tmp_path / "p.json"))


def test_service_state_survives_app_rebuild(tmp_path):
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    rev_path = str(tmp_path / "revocations.json")
    first = TestClient(create_app(public_key, revocations_path=rev_path))
    cid = credential["payload"]["credential_id"]
    first.post("/revoke", json={"credential_id": cid})
    rebuilt = TestClient(create_app(public_key, revocations_path=rev_path))
    assert rebuilt.post(
        "/verify", json={"credential": credential}).json() == {
        "ok": False, "reason": "revoked"}
    # The file on disk is valid in-memory format too.
    with open(rev_path, encoding="utf-8") as handle:
        assert json.load(handle)["entries"][0]["credential_id"] == cid
