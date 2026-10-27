"""Tests for the Know Your Agent v0.1 credential model and purchase policy."""

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from kya import (
    authorize_purchase,
    check_purchase,
    generate_keypair,
    issue_credential,
    load_private_key_pem,
    load_public_key_pem,
    private_key_to_pem,
    public_key_to_pem,
    verify_credential,
)


def make_keys():
    return generate_keypair()


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


def test_round_trip_verifies_ok():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    assert verify_credential(public_key, credential) == (True, "ok")


def test_json_round_trip_verifies_ok():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    reloaded = json.loads(json.dumps(credential))
    assert verify_credential(public_key, reloaded) == (True, "ok")


def test_key_pem_round_trip():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    restored_public = load_public_key_pem(public_key_to_pem(public_key))
    restored_private = load_private_key_pem(private_key_to_pem(private_key))
    assert verify_credential(restored_public, credential) == (True, "ok")
    assert verify_credential(
        restored_public, make_credential(restored_private)
    ) == (True, "ok")


def test_tampered_payload_rejected():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    tampered = copy.deepcopy(credential)
    tampered["payload"]["scope"]["max_amount_usd"] = 5000.0
    assert verify_credential(public_key, tampered) == (False, "bad_signature")


def test_tampered_signature_rejected():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    tampered = copy.deepcopy(credential)
    sig = tampered["signature"]
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered["signature"] = flipped
    assert verify_credential(public_key, tampered) == (False, "bad_signature")


def test_wrong_key_rejected():
    private_key, _ = make_keys()
    _, other_public = make_keys()
    credential = make_credential(private_key)
    assert verify_credential(other_public, credential) == (False, "bad_signature")


def test_expired_rejected():
    private_key, public_key = make_keys()
    now = datetime.now(timezone.utc)
    credential = make_credential(
        private_key,
        not_before=now - timedelta(hours=2),
        not_after=now - timedelta(hours=1),
    )
    assert verify_credential(public_key, credential) == (False, "expired")


def test_not_yet_valid_rejected():
    private_key, public_key = make_keys()
    now = datetime.now(timezone.utc)
    credential = make_credential(
        private_key,
        not_before=now + timedelta(hours=1),
        not_after=now + timedelta(hours=2),
    )
    assert verify_credential(public_key, credential) == (False, "not_yet_valid")


def test_malformed_rejected():
    _, public_key = make_keys()
    assert verify_credential(public_key, None) == (False, "malformed")
    assert verify_credential(public_key, {"payload": {}}) == (False, "malformed")
    assert verify_credential(
        public_key,
        {"payload": {}, "signature": "!!!", "algorithm": "Ed25519"},
    ) == (False, "malformed")
    assert verify_credential(
        public_key,
        {"payload": {}, "signature": "AAAA"},
    ) == (False, "unsupported_algorithm")


def test_revoked_id_rejected():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    revoked = {credential["payload"]["credential_id"]}
    assert verify_credential(public_key, credential, revoked_ids=revoked) == (
        False,
        "revoked",
    )
    assert verify_credential(public_key, credential, revoked_ids=set()) == (
        True,
        "ok",
    )


def test_issue_validates_inputs():
    private_key, _ = make_keys()
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        make_credential(private_key, agent_id="")
    with pytest.raises(ValueError):
        make_credential(private_key, scope={"max_amount_usd": -5})
    with pytest.raises(ValueError):
        make_credential(private_key, scope={"categories": "electronics"})
    with pytest.raises(ValueError):
        make_credential(
            private_key,
            not_before=now + timedelta(hours=1),
            not_after=now,
        )


def test_purchase_policy():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    payload = credential["payload"]
    assert check_purchase(payload, 30.0, "electronics") == (True, "allowed")
    assert check_purchase(payload, 500.0, "electronics") == (
        False,
        "amount_exceeds_scope",
    )
    assert check_purchase(payload, 30.0, "groceries") == (
        False,
        "category_not_allowed",
    )
    assert check_purchase(payload, 0, "electronics") == (False, "invalid_amount")


def test_authorize_purchase_end_to_end():
    private_key, public_key = make_keys()
    credential = make_credential(private_key)
    assert authorize_purchase(public_key, credential, 30.0, "electronics") == (
        True,
        "allowed",
    )
    assert authorize_purchase(public_key, credential, 500.0, "electronics") == (
        False,
        "amount_exceeds_scope",
    )
    revoked = {credential["payload"]["credential_id"]}
    assert authorize_purchase(
        public_key, credential, 30.0, "electronics", revoked_ids=revoked
    ) == (False, "revoked")
