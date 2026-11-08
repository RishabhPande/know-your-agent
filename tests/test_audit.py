"""Tests for Know Your Agent audit trail (kya/audit.py)."""

from datetime import datetime, timedelta, timezone

import pytest

from kya import (
    AuditLog,
    generate_keypair,
    issue_credential,
    verify_audit_entries,
    verify_credential,
)
from kya.audit import (
    AUDIT_BAD_HASH_CHAIN,
    AUDIT_BAD_INDEX,
    AUDIT_BAD_SIGNATURE,
    AUDIT_GENESIS_HASH,
    AUDIT_MALFORMED,
    AUDIT_OK,
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


def make_log(private_key):
    return AuditLog(private_key)


def test_append_chains_entries_and_verifies():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    log = make_log(private_key)
    first = log.record_issued(credential)
    ok, reason = verify_credential(public_key, credential)
    second = log.record_verified(credential, ok, reason)
    third = log.record_revoked(credential, reason="reported stolen")

    assert first["index"] == 0
    assert first["prev_hash"] == AUDIT_GENESIS_HASH
    assert first["kind"] == "issued"
    assert first["outcome"] == "issued"
    assert first["credential_id"] == credential["payload"]["credential_id"]
    assert second["index"] == 1
    assert second["prev_hash"] == first["entry_hash"]
    assert second["outcome"] == "ok"
    assert third["index"] == 2
    assert third["prev_hash"] == second["entry_hash"]
    assert third["detail"] == {"reason": "reported stolen"}
    assert len(log) == 3
    assert log.last_hash == third["entry_hash"]
    assert log.verify(public_key) == (True, AUDIT_OK)
    assert verify_audit_entries(public_key, log.to_dict()["entries"]) == (
        True,
        AUDIT_OK,
    )


def test_verified_entry_records_failure_reason():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    tampered = {
        "payload": dict(credential["payload"], agent_id="agent-impostor-99"),
        "signature": credential["signature"],
        "algorithm": credential["algorithm"],
    }
    ok, reason = verify_credential(public_key, tampered)
    assert (ok, reason) == (False, "bad_signature")
    log = make_log(private_key)
    entry = log.record_verified(tampered, ok, reason)
    # The tampered payload still names the impostor id; the log records
    # what was presented, and the outcome says it failed.
    assert entry["agent_id"] == "agent-impostor-99"
    assert entry["outcome"] == "bad_signature"
    assert log.verify(public_key) == (True, AUDIT_OK)


def test_recorded_times_normalize_to_utc_z():
    private_key, _ = generate_keypair()
    log = make_log(private_key)
    entry = log.append(
        "issued",
        "cred-1",
        agent_id="a",
        principal="u",
        outcome="issued",
        recorded_at=datetime(2026, 11, 1, 14, 30, 0, tzinfo=timezone.utc),
    )
    assert entry["recorded_at"] == "2026-11-01T14:30:00Z"
    entry2 = log.append(
        "revoked",
        "cred-1",
        agent_id="a",
        principal="u",
        outcome="revoked",
        recorded_at="2026-11-01T15:30:00+01:00",
    )
    assert entry2["recorded_at"] == "2026-11-01T14:30:00Z"


def test_append_rejects_bad_inputs():
    private_key, _ = generate_keypair()
    log = make_log(private_key)
    with pytest.raises(ValueError):
        log.append("shredded", "cred-1", agent_id="a", principal="u", outcome="x")
    with pytest.raises(ValueError):
        log.append("issued", "", agent_id="a", principal="u", outcome="issued")
    with pytest.raises(ValueError):
        log.append("issued", "cred-1", agent_id="", principal="u", outcome="issued")
    with pytest.raises(ValueError):
        log.append("issued", "cred-1", agent_id="a", principal="u", outcome="issued",
                   detail="not-a-dict")
    with pytest.raises(ValueError):
        log.append("issued", "cred-1", agent_id="a", principal="u", outcome="issued",
                   recorded_at="not-a-time")
    with pytest.raises(ValueError):
        log.record_issued(None)
    with pytest.raises(ValueError):
        log.record_issued({"payload": {}})
    with pytest.raises(ValueError):
        log.record_revoked(make_credential(private_key), reason=123)
    assert len(log) == 0


def test_keyless_log_cannot_append_but_can_verify():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    log.record_issued(make_credential(private_key))
    loaded = AuditLog.from_dict(log.to_dict())
    with pytest.raises(ValueError):
        loaded.record_issued(make_credential(private_key))
    assert loaded.verify(public_key) == (True, AUDIT_OK)


def test_tampering_with_a_field_breaks_the_chain():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    log.record_issued(make_credential(private_key))
    log.record_verified(make_credential(private_key), True, "ok")
    entries = log.entries()
    entries[0]["outcome"] = "revoked"
    assert verify_audit_entries(public_key, entries) == (
        False,
        AUDIT_BAD_HASH_CHAIN,
    )


def test_reordering_or_deleting_a_middle_entry_breaks_the_chain():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    credential = make_credential(private_key)
    log.record_issued(credential)
    log.record_verified(credential, True, "ok")
    log.record_revoked(credential)
    entries = log.entries()
    assert verify_audit_entries(public_key, entries[1:] + entries[:1]) == (
        False,
        AUDIT_BAD_INDEX,
    )
    del entries[1]
    # Deleting the middle entry breaks the index sequence first.
    assert verify_audit_entries(public_key, entries)[1] in (
        AUDIT_BAD_INDEX,
        AUDIT_BAD_HASH_CHAIN,
    )


def test_wrong_verifying_key_fails_signature_not_hash():
    private_key, public_key = generate_keypair()
    _, other_public = generate_keypair()
    log = make_log(private_key)
    log.record_issued(make_credential(private_key))
    # Hashes are intact, so the failure must be the signature.
    assert log.verify(other_public) == (False, AUDIT_BAD_SIGNATURE)


def test_recomputed_hash_with_forged_signature_fails():
    # An attacker who rewrites a field and recomputes the hash still
    # cannot forge the auditor's signature over the new content.
    import base64
    import hashlib

    from kya.credentials import _canonical_bytes

    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    log.record_issued(make_credential(private_key))
    entries = log.entries()
    entry = entries[0]
    entry["outcome"] = "revoked"
    content = {k: v for k, v in entry.items() if k not in ("entry_hash", "signature")}
    entry["entry_hash"] = hashlib.sha256(_canonical_bytes(content)).hexdigest()
    assert verify_audit_entries(public_key, entries) == (
        False,
        AUDIT_BAD_SIGNATURE,
    )


def test_tail_truncation_is_caught_only_by_an_anchor():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    credential = make_credential(private_key)
    log.record_issued(credential)
    log.record_verified(credential, True, "ok")
    anchor = log.last_hash
    entries = log.entries()
    # A truncated log still verifies on its own: a shorter chain is a
    # valid chain. The anchor is what catches the missing tail.
    assert verify_audit_entries(public_key, entries[:1]) == (True, AUDIT_OK)
    assert verify_audit_entries(
        public_key, entries[:1], expected_last_hash=anchor
    ) == (False, AUDIT_BAD_HASH_CHAIN)
    assert verify_audit_entries(
        public_key, entries, expected_last_hash=anchor
    ) == (True, AUDIT_OK)
    assert log.verify(public_key, expected_last_hash=anchor) == (True, AUDIT_OK)


def test_dict_and_json_round_trips_verify():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    credential = make_credential(private_key)
    log.record_issued(credential)
    log.record_verified(credential, True, "ok")
    log.record_revoked(credential, reason="agent decommissioned")

    restored = AuditLog.from_dict(log.to_dict())
    assert restored.entries() == log.entries()
    assert restored.verify(public_key) == (True, AUDIT_OK)

    from_json = AuditLog.from_json(log.to_json(), private_key)
    assert from_json.verify(public_key) == (True, AUDIT_OK)
    # A loaded log with a key keeps chaining from the last entry.
    new_entry = from_json.record_issued(make_credential(private_key))
    assert new_entry["index"] == 3
    assert new_entry["prev_hash"] == log.last_hash
    assert from_json.verify(public_key) == (True, AUDIT_OK)


def test_from_dict_rejects_malformed_logs():
    private_key, _ = generate_keypair()
    log = make_log(private_key)
    log.record_issued(make_credential(private_key))
    good = log.to_dict()
    with pytest.raises(ValueError):
        AuditLog.from_dict(None)
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 99, "entries": []})
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 1, "entries": "not-a-list"})
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 1, "entries": [dict(good["entries"][0], kind="nope")]})
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 1, "entries": [dict(good["entries"][0], index=5)]})
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 1, "entries": [dict(good["entries"][0], prev_hash="x")]})
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 1, "entries": [dict(good["entries"][0], signature="!!!")]})
    with pytest.raises(ValueError):
        AuditLog.from_json("{not json")
    # Two entries where the second does not link to the first.
    first, second = good["entries"][0], dict(good["entries"][0])
    second["index"] = 1
    with pytest.raises(ValueError):
        AuditLog.from_dict({"version": 1, "entries": [first, second]})


def test_verify_rejects_malformed_and_wrong_types():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    log.record_issued(make_credential(private_key))
    assert verify_audit_entries(public_key, "not-a-list") == (False, AUDIT_MALFORMED)
    assert verify_audit_entries(public_key, [None]) == (False, AUDIT_MALFORMED)
    assert verify_audit_entries(public_key, []) == (True, AUDIT_OK)
    assert verify_audit_entries(
        public_key, [], expected_last_hash=log.last_hash
    ) == (False, AUDIT_BAD_HASH_CHAIN)
    with pytest.raises(TypeError):
        verify_audit_entries(private_key, log.entries())


def test_entries_are_copies_and_get_handles_bounds():
    private_key, public_key = generate_keypair()
    log = make_log(private_key)
    credential = make_credential(private_key)
    log.record_issued(credential, detail={"note": "original"})
    entries = log.entries()
    entries[0]["detail"]["note"] = "tampered"
    entries[0]["outcome"] = "tampered"
    assert log.get(0)["detail"] == {"note": "original"}
    assert log.get(0)["outcome"] == "issued"
    assert log.verify(public_key) == (True, AUDIT_OK)
    assert log.get(1) is None
    assert log.get(-1) is None
    assert log.get("0") is None


def test_empty_log_last_hash_is_genesis():
    private_key, _ = generate_keypair()
    log = make_log(private_key)
    assert log.last_hash == AUDIT_GENESIS_HASH
    assert len(log) == 0


@pytest.mark.parametrize(
    'boundary',
    ['append_input', 'append_result', 'entries', 'get', 'to_dict', 'iterator',
     'constructor', 'from_dict'],
)
def test_nested_detail_is_detached_at_every_log_boundary(boundary):
    """Mutable nested JSON must never alias the signed internal record."""
    private_key, public_key = generate_keypair()
    detail = {'purchase': {'items': [{'sku': 'book', 'quantity': 1}]}}
    log = AuditLog(private_key)
    returned = log.append(
        'issued', 'credential-1', agent_id='agent-1', principal='user-1',
        outcome='issued', detail=detail,
        recorded_at='2026-11-08T12:00:00Z',
    )
    original_json = log.to_json()
    original_hash = log.last_hash

    if boundary == 'append_input':
        exposed = detail
    elif boundary == 'append_result':
        exposed = returned['detail']
    elif boundary == 'entries':
        exposed = log.entries()[0]['detail']
    elif boundary == 'get':
        exposed = log.get(0)['detail']
    elif boundary == 'to_dict':
        exposed = log.to_dict()['entries'][0]['detail']
    elif boundary == 'iterator':
        exposed = next(iter(log))['detail']
    else:
        serialized = log.to_dict()
        if boundary == 'constructor':
            log = AuditLog(entries=serialized['entries'])
        else:
            log = AuditLog.from_dict(serialized)
        exposed = serialized['entries'][0]['detail']

    exposed['purchase']['items'][0]['quantity'] = 99
    exposed['purchase']['items'].append({'sku': 'other', 'quantity': 2})

    assert log.to_json() == original_json
    assert log.last_hash == original_hash
    assert log.verify(public_key, expected_last_hash=original_hash) == (True, AUDIT_OK)
