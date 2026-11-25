"""Tests for state endpoint authentication (kya/remote.py, service/app.py).

The shared state backend shipped unauthenticated: anyone who could
reach it could read the revocation list, revoke a credential, or
burn a presentation id. An optional shared bearer token now guards
it on both sides: ``create_app(state_token=...)`` on the service and
``auth_token=...`` on the remote stores and the in-process
transport. These tests pin the shape: no token configured means the
old open behaviour, a configured token means 401 without it and
RemoteStateError on a client that cannot or will not present it,
and the token never leaks into other endpoints.
"""

import urllib.request

import pytest
from fastapi.testclient import TestClient

import kya.remote as remote_module
from kya import (
    InProcessTransport,
    RemoteReplayStore,
    RemoteRevocationList,
    RemoteStateError,
    generate_keypair,
)
from service.app import create_app

TOKEN = "test-state-token"
AUTH = {"Authorization": "Bearer " + TOKEN}
WRONG = {"Authorization": "Bearer wrong-token"}


def _client(state_token=TOKEN):
    _private_key, public_key = generate_keypair()
    return TestClient(create_app(public_key, state_token=state_token))


# -- service side -------------------------------------------------------------


def test_state_endpoints_require_token_when_configured():
    client = _client()
    assert client.get("/state/revocations").status_code == 401
    assert client.get("/state/revocations/cred-1").status_code == 401
    assert client.get("/state/replay").status_code == 401
    assert client.post(
        "/state/revocations", json={"credential_id": "cred-1"}
    ).status_code == 401
    assert client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
    ).status_code == 401
    assert client.post(
        "/state/replay/lookup",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
    ).status_code == 401
    assert client.post(
        "/state/replay/prune", json={"seen_before": "2026-11-25T00:00:00Z"}
    ).status_code == 401


def test_wrong_token_and_wrong_scheme_are_401():
    client = _client()
    assert client.get("/state/revocations", headers=WRONG).status_code == 401
    basic = {"Authorization": "Basic " + TOKEN}
    assert client.get("/state/revocations", headers=basic).status_code == 401
    response = client.get("/state/revocations")
    assert response.headers.get("www-authenticate") == "Bearer"


def test_correct_token_serves_the_state_contract():
    client = _client()
    assert client.get("/state/revocations", headers=AUTH).json() == {
        "version": 1,
        "entries": [],
    }
    made = client.post(
        "/state/revocations",
        json={"credential_id": "cred-1", "reason": "reported stolen"},
        headers=AUTH,
    )
    assert made.status_code == 200
    assert made.json()["revoked"] is True
    lookup = client.get("/state/revocations/cred-1", headers=AUTH)
    assert lookup.json()["revoked"] is True
    recorded = client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
        headers=AUTH,
    )
    assert recorded.json() == {"is_new": True}


def test_unauthenticated_attempt_changes_no_state():
    client = _client()
    client.post("/state/revocations", json={"credential_id": "cred-1"})
    client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
    )
    assert client.get("/state/revocations", headers=AUTH).json() == {
        "version": 1,
        "entries": [],
    }
    assert client.get("/state/replay", headers=AUTH).json() == {
        "version": 1,
        "entries": [],
    }


def test_token_does_not_gate_other_endpoints():
    _private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key, state_token=TOKEN))
    assert client.get("/health").json() == {"status": "ok"}
    revoked = client.post("/revoke", json={"credential_id": "cred-1"})
    assert revoked.status_code == 200


def test_no_token_configured_keeps_state_endpoints_open():
    client = _client(state_token=None)
    assert client.get("/state/revocations").status_code == 200
    assert client.get("/state/replay").status_code == 200


def test_state_token_must_be_a_non_empty_string():
    _private_key, public_key = generate_keypair()
    with pytest.raises(ValueError):
        create_app(public_key, state_token="")
    with pytest.raises(ValueError):
        create_app(public_key, state_token=42)


# -- in-process backend ---------------------------------------------------------


def _authenticated_machines():
    backend = InProcessTransport(auth_token=TOKEN)
    rev_a = RemoteRevocationList(transport=backend, auth_token=TOKEN)
    rev_b = RemoteRevocationList(transport=backend, auth_token=TOKEN)
    replay_a = RemoteReplayStore(transport=backend, auth_token=TOKEN)
    replay_b = RemoteReplayStore(transport=backend, auth_token=TOKEN)
    return rev_a, rev_b, replay_a, replay_b


def test_authenticated_remote_stores_agree_across_machines():
    rev_a, rev_b, replay_a, replay_b = _authenticated_machines()
    assert rev_a.revoke("cred-1", reason="reported stolen") is True
    assert rev_b.is_revoked("cred-1") is True
    assert replay_a.check_and_record("cred-1", "p-1") is True
    assert replay_b.check_and_record("cred-1", "p-1") is False


def test_missing_or_wrong_token_fails_closed_at_construction():
    backend = InProcessTransport(auth_token=TOKEN)
    with pytest.raises(RemoteStateError):
        RemoteRevocationList(transport=backend)
    with pytest.raises(RemoteStateError):
        RemoteReplayStore(transport=backend, auth_token="wrong-token")
    status, _parsed = backend("GET", "/state/revocations", None)
    assert status == 401


def test_open_backend_still_accepts_tokenless_stores():
    backend = InProcessTransport()
    revocations = RemoteRevocationList(transport=backend)
    assert revocations.revoked_ids() == set()


def test_auth_token_must_be_a_non_empty_string():
    backend = InProcessTransport()
    with pytest.raises(ValueError):
        RemoteRevocationList(transport=backend, auth_token="")
    with pytest.raises(ValueError):
        InProcessTransport(auth_token=42)


def test_transport_that_cannot_carry_headers_fails_closed():
    def three_arg_transport(method, path, payload):
        return 200, {"version": 1, "entries": []}

    with pytest.raises(RemoteStateError):
        RemoteRevocationList(
            transport=three_arg_transport, auth_token=TOKEN
        )


def test_backend_401_is_remote_state_error_not_value_error():
    def unauthorized(method, path, payload, headers=None):
        return 401, {"detail": "state endpoints require authentication"}

    with pytest.raises(RemoteStateError):
        RemoteRevocationList(transport=unauthorized, auth_token=TOKEN)


# -- HTTP transport -------------------------------------------------------------


def _header_transport(client, token):
    def transport(method, path, payload, headers=None):
        response = client.request(
            method, path, json=payload, headers=headers or {}
        )
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None

    return transport


def test_remote_stores_against_authenticated_http_service():
    client = _client()
    transport = _header_transport(client, TOKEN)
    revocations = RemoteRevocationList(transport=transport, auth_token=TOKEN)
    replay = RemoteReplayStore(transport=transport, auth_token=TOKEN)
    assert revocations.revoke("cred-1") is True
    assert replay.check_and_record("cred-1", "p-1") is True
    # The service state itself moved, so the two sides agree.
    assert client.get(
        "/state/revocations/cred-1", headers=AUTH
    ).json()["revoked"] is True

    anonymous = _header_transport(client, None)
    with pytest.raises(RemoteStateError):
        RemoteRevocationList(transport=anonymous)


def test_urllib_transport_sends_the_bearer_header(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"version": 1, "entries": []}'

    def fake_urlopen(request, timeout=None):
        captured["authorization"] = request.get_header("Authorization")
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    revocations = RemoteRevocationList(
        "http://state.internal:8000", auth_token=TOKEN
    )
    assert captured["authorization"] == "Bearer " + TOKEN
    assert revocations.revoked_ids() == set()
    assert remote_module._transport_accepts_headers(
        revocations._transport
    ) is True
