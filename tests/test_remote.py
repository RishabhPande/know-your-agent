"""Tests for cross-machine shared state (kya/remote.py)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from kya import (
    InProcessTransport,
    RemoteReplayStore,
    RemoteRevocationList,
    RemoteStateError,
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


def two_machines():
    """Two remote store pairs sharing one in-process backend."""
    backend = InProcessTransport()
    rev_a = RemoteRevocationList(transport=backend)
    rev_b = RemoteRevocationList(transport=backend)
    replay_a = RemoteReplayStore(transport=backend)
    replay_b = RemoteReplayStore(transport=backend)
    return rev_a, rev_b, replay_a, replay_b


# -- remote revocations ------------------------------------------------------


def test_revocation_on_one_machine_seen_on_other():
    rev_a, rev_b, _ra, _rb = two_machines()
    assert rev_a.revoke("cred-1", reason="reported stolen") is True
    assert rev_b.is_revoked("cred-1") is True
    assert rev_b.get("cred-1")["reason"] == "reported stolen"
    assert rev_b.revoked_ids() == {"cred-1"}
    assert len(rev_b) == 1
    assert "cred-1" in rev_b


def test_double_revoke_across_machines_keeps_first_entry():
    rev_a, rev_b, _ra, _rb = two_machines()
    assert rev_a.revoke("cred-1", reason="first") is True
    assert rev_b.revoke("cred-1", reason="second") is False
    assert rev_a.get("cred-1")["reason"] == "first"


def test_remote_revocation_blocks_verification_on_other_machine():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    rev_a, rev_b, _ra, _rb = two_machines()
    ok, _reason = verify_credential(public_key, credential, revoked_ids=rev_b)
    assert ok is True
    rev_a.revoke_credential(credential, reason="reported stolen")
    ok, reason = verify_credential(public_key, credential, revoked_ids=rev_b)
    assert (ok, reason) == (False, "revoked")


def test_remote_revocation_round_trip_matches_local_format():
    rev_a, _rev_b, _ra, _rb = two_machines()
    rev_a.revoke("cred-1", revoked_at="2026-11-23T08:00:00Z")
    restored = RevocationList.from_json(rev_a.to_json())
    assert restored.revoked_ids() == {"cred-1"}
    assert rev_a.entries() == restored.entries()
    assert rev_a.get("missing") is None
    assert rev_a.is_revoked(123) is False


def test_remote_revocation_validates_locally():
    rev_a, _rev_b, _ra, _rb = two_machines()
    with pytest.raises(ValueError):
        rev_a.revoke("")
    with pytest.raises(ValueError):
        rev_a.revoke("cred-1", reason=42)
    with pytest.raises(ValueError):
        rev_a.revoke("cred-1", revoked_at="not-a-time")
    with pytest.raises(ValueError):
        rev_a.revoke_credential({"no": "payload"})


# -- remote replay ------------------------------------------------------------


def test_replay_on_one_machine_seen_on_other():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    _a, _b, replay_a, replay_b = two_machines()
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=replay_a, presentation_id="order-1",
    )
    assert (ok, reason) == (True, "allowed")
    credential_id = credential["payload"]["credential_id"]
    assert replay_b.is_seen(credential_id, "order-1") is True


def test_same_presentation_rejected_on_other_machine():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    _a, _b, replay_a, replay_b = two_machines()
    first = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=replay_a, presentation_id="order-1",
    )
    second = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=replay_b, presentation_id="order-1",
    )
    assert first == (True, "allowed")
    assert second == (False, "replay")


def test_remote_replay_check_and_record_and_prune():
    _a, _b, replay_a, replay_b = two_machines()
    assert replay_a.check_and_record(
        "cred-1", "p-1", seen_at="2026-11-23T08:00:00Z"
    ) is True
    assert replay_b.check_and_record("cred-1", "p-1") is False
    assert replay_b.check_and_record("cred-1", "p-2") is True
    assert len(replay_a) == 2
    assert replay_b.prune(seen_before="2026-11-23T09:00:00Z") == 1
    assert len(replay_a) == 1
    restored = ReplayStore.from_json(replay_a.to_json())
    assert len(restored) == 1


def test_remote_replay_validates_locally():
    _a, _b, replay_a, _rb = two_machines()
    with pytest.raises(ValueError):
        replay_a.check_and_record("", "p-1")
    with pytest.raises(ValueError):
        replay_a.check_and_record("cred-1", "")
    with pytest.raises(ValueError):
        replay_a.prune(seen_before="not-a-time")
    assert replay_a.is_seen(1, "p-1") is False


# -- fail closed ----------------------------------------------------------------


def _dead_transport(method, path, payload):
    raise ConnectionError("backend down")


def test_unreachable_backend_fails_closed():
    with pytest.raises(RemoteStateError):
        RemoteRevocationList(transport=_dead_transport)
    with pytest.raises(RemoteStateError):
        RemoteReplayStore(transport=_dead_transport)


def test_backend_failure_after_connect_fails_closed():
    backend = InProcessTransport()
    revocations = RemoteRevocationList(transport=backend)
    revocations._transport = _dead_transport
    with pytest.raises(RemoteStateError):
        revocations.is_revoked("cred-1")
    with pytest.raises(RemoteStateError):
        revocations.revoked_ids()


def test_malformed_backend_answers_fail_closed():
    def garbage(method, path, payload):
        return 200, {"unexpected": True}

    with pytest.raises((RemoteStateError, ValueError)):
        RemoteRevocationList(transport=garbage)

    def wrong_bool(method, path, payload):
        if path == "/state/revocations":
            return 200, {"version": 1, "entries": []}
        return 200, {"revoked": "yes"}

    revocations = RemoteRevocationList(transport=wrong_bool)
    with pytest.raises(RemoteStateError):
        revocations.is_revoked("cred-1")

    def error_status(method, path, payload):
        return 500, {"detail": "boom"}

    with pytest.raises(RemoteStateError):
        RemoteReplayStore(transport=error_status)


def test_backend_validation_rejection_is_value_error():
    def rejecting(method, path, payload):
        if method == "GET":
            return 200, {"version": 1, "entries": []}
        return 422, {"detail": "bad id"}

    revocations = RemoteRevocationList(transport=rejecting)
    with pytest.raises(ValueError):
        revocations.revoke("cred-1")


def test_constructor_requires_exactly_one_route():
    with pytest.raises(ValueError):
        RemoteRevocationList()
    with pytest.raises(ValueError):
        RemoteRevocationList(
            "http://127.0.0.1:9", transport=InProcessTransport()
        )
    with pytest.raises(ValueError):
        RemoteReplayStore(transport="not-callable")


def test_in_process_transport_unknown_path_is_404():
    backend = InProcessTransport()
    status, _parsed = backend("GET", "/state/nope", None)
    assert status == 404


# -- HTTP service as the backend --------------------------------------------------


def _testclient_transport(client):
    def transport(method, path, payload):
        response = client.request(method, path, json=payload)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None

    return transport


def test_remote_stores_against_http_service():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    client = TestClient(create_app(public_key))
    transport = _testclient_transport(client)
    revocations = RemoteRevocationList(transport=transport)
    replay = RemoteReplayStore(transport=transport)

    # A purchase spent through the remote store is spent for the
    # service itself, because both sides share the service state.
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics",
        replay_store=replay, presentation_id="order-9",
    )
    assert (ok, reason) == (True, "allowed")
    spent = client.post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 30.0,
            "category": "electronics",
            "presentation_id": "order-9",
        },
    )
    assert spent.json() == {"accepted": False, "reason": "replay"}

    # A revocation made through the remote store is enforced by the
    # service's own verify endpoint.
    assert revocations.revoke_credential(credential) is True
    checked = client.post("/verify", json={"credential": credential})
    assert checked.json() == {"ok": False, "reason": "revoked"}


def test_state_endpoints_validate_and_report():
    _private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    assert client.get("/state/revocations").json() == {
        "version": 1,
        "entries": [],
    }
    bad = client.post(
        "/state/revocations", json={"credential_id": ""}
    )
    assert bad.status_code == 422
    bad = client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": ""},
    )
    assert bad.status_code == 422
    lookup = client.get("/state/revocations/cred-9")
    assert lookup.json() == {"revoked": False, "entry": None}
