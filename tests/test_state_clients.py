"""Tests for per-client state tokens (kya/remote.py, service/app.py).

State endpoint authentication shipped as one shared bearer token:
every machine held the same secret, so the backend could not tell
machines apart, could not give a machine read-only access, and
rotating the token meant touching every machine at once. A backend
can now name its clients instead: each client has its own token
and a set of scopes, read or write. These tests pin the shape:
an unknown token is a 401, a known client outside its scopes is
a 403 and changes no state, read covers GETs and the replay
lookup while write covers the mutations, and the single-token
and open configurations keep their old behaviour.
"""

import pytest
from fastapi.testclient import TestClient

from kya import (
    STATE_SCOPES,
    InProcessTransport,
    RemoteReplayStore,
    RemoteRevocationList,
    RemoteStateError,
    generate_keypair,
)
from service.app import create_app

CLIENTS = {
    "machine-writer": {"token": "writer-token", "scopes": ["read", "write"]},
    "machine-reader": {"token": "reader-token", "scopes": ["read"]},
}
WRITER = {"Authorization": "Bearer writer-token"}
READER = {"Authorization": "Bearer reader-token"}


def _client(**kwargs):
    _private_key, public_key = generate_keypair()
    return TestClient(create_app(public_key, **kwargs))


# -- service side -------------------------------------------------------------


def test_state_scopes_are_read_and_write():
    assert STATE_SCOPES == frozenset({"read", "write"})


def test_writer_can_read_and_write_state():
    client = _client(state_clients=CLIENTS)
    made = client.post(
        "/state/revocations", json={"credential_id": "cred-1"}, headers=WRITER
    )
    assert made.status_code == 200
    assert client.get("/state/revocations", headers=WRITER).status_code == 200
    recorded = client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
        headers=WRITER,
    )
    assert recorded.json() == {"is_new": True}


def test_reader_can_read_but_not_write():
    client = _client(state_clients=CLIENTS)
    client.post(
        "/state/revocations", json={"credential_id": "cred-1"}, headers=WRITER
    )
    assert client.get("/state/revocations", headers=READER).status_code == 200
    lookup = client.get("/state/revocations/cred-1", headers=READER)
    assert lookup.json()["revoked"] is True
    assert client.get("/state/replay", headers=READER).status_code == 200
    assert client.post(
        "/state/revocations", json={"credential_id": "cred-2"}, headers=READER
    ).status_code == 403
    assert client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
        headers=READER,
    ).status_code == 403
    assert client.post(
        "/state/replay/prune",
        json={"seen_before": "2026-11-27T00:00:00Z"},
        headers=READER,
    ).status_code == 403


def test_reader_replay_lookup_is_a_read():
    client = _client(state_clients=CLIENTS)
    client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
        headers=WRITER,
    )
    seen = client.post(
        "/state/replay/lookup",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
        headers=READER,
    )
    assert seen.json() == {"seen": True}


def test_unknown_token_is_401_and_known_token_wrong_scope_is_403():
    client = _client(state_clients=CLIENTS)
    unknown = {"Authorization": "Bearer no-such-token"}
    assert client.get("/state/revocations", headers=unknown).status_code == 401
    assert client.get("/state/revocations").status_code == 401
    forbidden = client.post(
        "/state/revocations", json={"credential_id": "cred-1"}, headers=READER
    )
    assert forbidden.status_code == 403
    assert forbidden.headers.get("www-authenticate") is None


def test_forbidden_attempt_changes_no_state():
    client = _client(state_clients=CLIENTS)
    client.post(
        "/state/revocations", json={"credential_id": "cred-1"}, headers=READER
    )
    client.post(
        "/state/replay/check-and-record",
        json={"credential_id": "cred-1", "presentation_id": "p-1"},
        headers=READER,
    )
    assert client.get("/state/revocations", headers=WRITER).json() == {
        "version": 1,
        "entries": [],
    }
    assert client.get("/state/replay", headers=WRITER).json() == {
        "version": 1,
        "entries": [],
    }


def test_write_only_client_cannot_read():
    clients = {"writer-only": {"token": "w-only", "scopes": ["write"]}}
    client = _client(state_clients=clients)
    headers = {"Authorization": "Bearer w-only"}
    assert client.post(
        "/state/revocations", json={"credential_id": "cred-1"}, headers=headers
    ).status_code == 200
    # Building a remote store starts with a read, so a write-only
    # client cannot even construct one against this backend shape.
    assert client.get("/state/revocations", headers=headers).status_code == 403


def test_state_clients_validation():
    _private_key, public_key = generate_keypair()
    with pytest.raises(ValueError):
        create_app(public_key, state_token="shared", state_clients=CLIENTS)
    with pytest.raises(ValueError):
        create_app(public_key, state_clients={})
    with pytest.raises(ValueError):
        create_app(public_key, state_clients={"a": {"token": "", "scopes": ["read"]}})
    with pytest.raises(ValueError):
        create_app(public_key, state_clients={"a": {"token": "t", "scopes": ["admin"]}})
    with pytest.raises(ValueError):
        create_app(public_key, state_clients={"a": {"token": "t", "scopes": []}})
    with pytest.raises(ValueError):
        create_app(public_key, state_clients={"a": {"token": "t", "scopes": "read"}})
    with pytest.raises(ValueError):
        create_app(
            public_key,
            state_clients={
                "a": {"token": "same", "scopes": ["read"]},
                "b": {"token": "same", "scopes": ["write"]},
            },
        )


def test_clients_mode_does_not_gate_other_endpoints():
    client = _client(state_clients=CLIENTS)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.post(
        "/revoke", json={"credential_id": "cred-1"}
    ).status_code == 200


# -- in-process backend ---------------------------------------------------------


def _scoped_machines():
    backend = InProcessTransport(auth_clients=CLIENTS)
    writer = RemoteRevocationList(transport=backend, auth_token="writer-token")
    reader = RemoteRevocationList(transport=backend, auth_token="reader-token")
    return backend, writer, reader


def test_scoped_remote_stores_agree_across_machines():
    _backend, writer, reader = _scoped_machines()
    assert writer.revoke("cred-1", reason="reported stolen") is True
    assert reader.is_revoked("cred-1") is True
    assert reader.revoked_ids() == {"cred-1"}


def test_reader_store_cannot_revoke_and_changes_nothing():
    backend, writer, reader = _scoped_machines()
    with pytest.raises(RemoteStateError):
        reader.revoke("cred-9")
    assert writer.is_revoked("cred-9") is False
    status, _parsed = backend(
        "POST", "/state/revocations", {"credential_id": "cred-9"},
        {"Authorization": "Bearer reader-token"},
    )
    assert status == 403


def test_reader_replay_store_can_look_up_but_not_record():
    backend = InProcessTransport(auth_clients=CLIENTS)
    writer = RemoteReplayStore(transport=backend, auth_token="writer-token")
    reader = RemoteReplayStore(transport=backend, auth_token="reader-token")
    assert writer.check_and_record("cred-1", "p-1") is True
    assert reader.is_seen("cred-1", "p-1") is True
    with pytest.raises(RemoteStateError):
        reader.check_and_record("cred-1", "p-2")
    with pytest.raises(RemoteStateError):
        reader.prune(seen_before="2026-11-27T00:00:00Z")


def test_unknown_token_fails_closed_at_construction():
    backend = InProcessTransport(auth_clients=CLIENTS)
    with pytest.raises(RemoteStateError):
        RemoteRevocationList(transport=backend, auth_token="no-such-token")
    with pytest.raises(RemoteStateError):
        RemoteRevocationList(transport=backend)
    status, _parsed = backend("GET", "/state/revocations", None)
    assert status == 401


def test_auth_clients_validation_and_exclusivity():
    with pytest.raises(ValueError):
        InProcessTransport(auth_token="shared", auth_clients=CLIENTS)
    with pytest.raises(ValueError):
        InProcessTransport(auth_clients={"a": {"token": "t", "scopes": ["bogus"]}})


# -- HTTP transport -------------------------------------------------------------


def _header_transport(client):
    def transport(method, path, payload, headers=None):
        response = client.request(
            method, path, json=payload, headers=headers or {}
        )
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None

    return transport


def test_remote_stores_against_scoped_http_service():
    client = _client(state_clients=CLIENTS)
    transport = _header_transport(client)
    writer = RemoteRevocationList(transport=transport, auth_token="writer-token")
    reader = RemoteRevocationList(transport=transport, auth_token="reader-token")
    assert writer.revoke("cred-1") is True
    assert reader.is_revoked("cred-1") is True
    with pytest.raises(RemoteStateError):
        reader.revoke("cred-2")
    assert client.get(
        "/state/revocations/cred-2", headers=WRITER
    ).json()["revoked"] is False
