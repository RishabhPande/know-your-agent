"""Tests for Know Your Agent delegation chains (kya/delegation.py)."""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from kya import (
    authorize_purchase_chain,
    delegate_credential,
    generate_keypair,
    issue_credential,
    scope_is_subset,
    verify_chain,
)


def make_keys():
    return generate_keypair()


def root_credential(private_key, **overrides):
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


def delegate(private_key, parent, **overrides):
    now = datetime.now(timezone.utc)
    args = {
        "agent_id": "agent-sub-01",
        "scope": {"max_amount_usd": 20.0, "categories": ["electronics"]},
        "not_before": now,
        "not_after": now + timedelta(minutes=30),
    }
    args.update(overrides)
    return delegate_credential(private_key, parent, **args)


def test_two_level_chain_verifies():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    child = delegate(private_key, root)
    assert verify_chain(public_key, [root, child]) == (True, "ok")
    assert child["payload"]["delegated_from"] == root["payload"]["credential_id"]
    assert child["payload"]["delegator_agent_id"] == "agent-shopper-01"
    assert child["payload"]["principal"] == "user-123"


def test_three_level_chain_narrows_each_step():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    child = delegate(private_key, root)
    now = datetime.now(timezone.utc)
    grandchild = delegate(
        private_key,
        child,
        agent_id="agent-sub-02",
        scope={"max_amount_usd": 10.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=15),
    )
    assert verify_chain(public_key, [root, child, grandchild]) == (True, "ok")


def test_single_root_is_a_valid_chain():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    assert verify_chain(public_key, [root]) == (True, "ok")


def test_empty_and_malformed_chains_rejected():
    _, public_key = make_keys()
    assert verify_chain(public_key, []) == (False, "malformed")
    assert verify_chain(public_key, None) == (False, "malformed")
    assert verify_chain(public_key, ["not-a-credential"]) == (False, "malformed")


def test_delegate_widened_amount_raises():
    private_key, _ = make_keys()
    root = root_credential(private_key)
    with pytest.raises(ValueError):
        delegate(
            private_key, root, scope={"max_amount_usd": 500.0, "categories": ["electronics"]}
        )


def test_delegate_widened_category_raises():
    private_key, _ = make_keys()
    root = root_credential(private_key)
    with pytest.raises(ValueError):
        delegate(
            private_key,
            root,
            scope={"max_amount_usd": 20.0, "categories": ["electronics", "groceries"]},
        )


def test_delegate_dropped_category_limit_raises():
    # Dropping the categories list entirely would lift the restriction.
    private_key, _ = make_keys()
    root = root_credential(private_key)
    with pytest.raises(ValueError):
        delegate(private_key, root, scope={"max_amount_usd": 20.0})


def test_delegate_widened_window_raises():
    private_key, _ = make_keys()
    now = datetime.now(timezone.utc)
    root = root_credential(private_key)
    with pytest.raises(ValueError):
        delegate(
            private_key, root, not_before=now - timedelta(hours=2), not_after=now
        )
    with pytest.raises(ValueError):
        delegate(
            private_key,
            root,
            not_before=now,
            not_after=now + timedelta(hours=5),
        )


def test_chain_rejects_widened_scope_issued_directly():
    # Defense in depth: verify_chain must catch a widened link even when
    # it was signed directly via issue_credential, bypassing delegate_*.
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    now = datetime.now(timezone.utc)
    widened = issue_credential(
        private_key,
        agent_id="agent-sub-01",
        principal="user-123",
        scope={"max_amount_usd": 500.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=30),
        delegated_from=root["payload"]["credential_id"],
        delegator_agent_id="agent-shopper-01",
    )
    assert verify_chain(public_key, [root, widened]) == (False, "scope_widened")


def test_chain_rejects_widened_window_issued_directly():
    private_key, public_key = make_keys()
    now = datetime.now(timezone.utc)
    root = root_credential(private_key)
    widened = issue_credential(
        private_key,
        agent_id="agent-sub-01",
        principal="user-123",
        scope={"max_amount_usd": 20.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(hours=5),
        delegated_from=root["payload"]["credential_id"],
        delegator_agent_id="agent-shopper-01",
    )
    assert verify_chain(public_key, [root, widened]) == (False, "window_widened")


def test_chain_rejects_principal_change():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    now = datetime.now(timezone.utc)
    other_principal = issue_credential(
        private_key,
        agent_id="agent-sub-01",
        principal="user-999",
        scope={"max_amount_usd": 20.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=30),
        delegated_from=root["payload"]["credential_id"],
        delegator_agent_id="agent-shopper-01",
    )
    assert verify_chain(public_key, [root, other_principal]) == (
        False,
        "principal_mismatch",
    )


def test_chain_rejects_broken_link():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    child = delegate(private_key, root)
    other_root = root_credential(private_key, agent_id="agent-other-01")
    # Child linked to root, presented after an unrelated credential.
    assert verify_chain(public_key, [other_root, child]) == (False, "bad_chain")
    # A lone delegated credential, parent missing from the chain.
    assert verify_chain(public_key, [child]) == (False, "bad_chain")
    # Reordered chain.
    assert verify_chain(public_key, [child, root]) == (False, "bad_chain")


def test_chain_rejects_tampered_link():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    child = delegate(private_key, root)
    tampered = copy.deepcopy(child)
    tampered["payload"]["scope"]["max_amount_usd"] = 5000.0
    assert verify_chain(public_key, [root, tampered]) == (False, "bad_signature")


def test_chain_rejects_revoked_middle_link():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    child = delegate(private_key, root)
    now = datetime.now(timezone.utc)
    grandchild = delegate(
        private_key,
        child,
        agent_id="agent-sub-02",
        scope={"max_amount_usd": 10.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=15),
    )
    revoked = {child["payload"]["credential_id"]}
    assert verify_chain(public_key, [root, child, grandchild], revoked_ids=revoked) == (
        False,
        "revoked",
    )
    # Revoking the root invalidates the whole chain.
    revoked_root = {root["payload"]["credential_id"]}
    assert verify_chain(
        public_key, [root, child, grandchild], revoked_ids=revoked_root
    ) == (False, "revoked")


def test_authorize_purchase_through_leaf_scope():
    private_key, public_key = make_keys()
    root = root_credential(private_key)
    child = delegate(private_key, root)
    chain = [root, child]
    # $15 is inside the leaf's $20 limit, even though root allows $50.
    assert authorize_purchase_chain(public_key, chain, 15.0, "electronics") == (
        True,
        "allowed",
    )
    # $30 is inside the root's limit but outside the leaf's: rejected.
    assert authorize_purchase_chain(public_key, chain, 30.0, "electronics") == (
        False,
        "amount_exceeds_scope",
    )
    assert authorize_purchase_chain(public_key, chain, 15.0, "groceries") == (
        False,
        "category_not_allowed",
    )


def test_scope_is_subset_semantics():
    parent = {"max_amount_usd": 50.0, "categories": ["electronics", "books"]}
    assert scope_is_subset(parent, {"max_amount_usd": 50.0, "categories": ["electronics"]})
    assert scope_is_subset(parent, {"max_amount_usd": 20.0, "categories": ["books"]})
    assert not scope_is_subset(parent, {"max_amount_usd": 51.0, "categories": ["electronics"]})
    assert not scope_is_subset(parent, {"max_amount_usd": 20.0, "categories": ["groceries"]})
    # Dropping a restriction entirely is widening.
    assert not scope_is_subset(parent, {"max_amount_usd": 20.0})
    assert not scope_is_subset(parent, {"categories": ["electronics"]})
    # Unrestricted parent: any finite limit narrows it.
    assert scope_is_subset({"categories": ["electronics"]}, {"max_amount_usd": 10.0, "categories": ["electronics"]})
    assert scope_is_subset({"max_amount_usd": 50.0}, {"max_amount_usd": 50.0, "categories": ["electronics"]})
    # Unknown keys: no new keys, no changed values.
    assert not scope_is_subset(parent, dict(parent, new_capability=True))
    assert scope_is_subset(
        dict(parent, region="us"), dict(parent, region="us")
    )
    assert not scope_is_subset(
        dict(parent, region="us"), dict(parent, region="eu")
    )


def test_nan_child_limit_cannot_widen_chain():
    from datetime import datetime, timezone
    from kya import (generate_keypair, issue_credential, delegate_credential,
                     authorize_purchase_chain)
    sk, pk = generate_keypair()
    root = issue_credential(sk, agent_id="a", principal="u",
                            scope={"max_amount_usd": 10.0, "categories": ["e"]},
                            not_before="2026-10-27T00:00:00Z", not_after="2026-10-27T01:00:00Z")
    try:
        child = delegate_credential(sk, root, agent_id="b",
                                    scope={"max_amount_usd": float("nan"), "categories": ["e"]},
                                    not_before="2026-10-27T00:00:00Z", not_after="2026-10-27T00:30:00Z")
    except ValueError:
        return
    now = datetime(2026, 10, 27, 0, 10, tzinfo=timezone.utc)
    ok, _ = authorize_purchase_chain(pk, [root, child], 5000, "e", now=now)
    assert not ok


def _sign_raw(sk, payload):
    """Sign an arbitrary payload the way issue_credential does, skipping its checks."""
    import base64
    from kya.credentials import _canonical_bytes
    sig = base64.urlsafe_b64encode(sk.sign(_canonical_bytes(payload))).decode()
    return {"payload": payload, "signature": sig, "algorithm": "Ed25519"}


def _raw_payload(cid, scope, **extra):
    p = {"version": 1, "credential_id": cid, "agent_id": "a-" + cid, "principal": "u",
         "issuer": "kya", "scope": scope, "not_before": "2026-10-27T00:00:00Z",
         "not_after": "2026-10-27T01:00:00Z", "issued_at": "2026-10-27T00:00:00Z"}
    p.update(extra)
    return p


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_externally_signed_nonfinite_scope_fails_verification(bad):
    from datetime import datetime, timezone
    from kya import generate_keypair, verify_credential, authorize_purchase
    sk, pk = generate_keypair()
    cred = _sign_raw(sk, _raw_payload("x", {"max_amount_usd": bad, "categories": ["e"]}))
    now = datetime(2026, 10, 27, 0, 10, tzinfo=timezone.utc)
    assert verify_credential(pk, cred, now=now) == (False, "bad_scope")
    assert authorize_purchase(pk, cred, 5000, "e", now=now)[0] is False


def test_externally_signed_nan_child_fails_chain():
    from datetime import datetime, timezone
    from kya import generate_keypair, verify_chain
    sk, pk = generate_keypair()
    root = _sign_raw(sk, _raw_payload("r", {"max_amount_usd": 10.0, "categories": ["e"]}))
    child = _sign_raw(sk, _raw_payload("c", {"max_amount_usd": float("nan"), "categories": ["e"]},
                                       delegated_from="r", delegator_agent_id="a-r"))
    now = datetime(2026, 10, 27, 0, 10, tzinfo=timezone.utc)
    ok, _ = verify_chain(pk, [root, child], now=now)
    assert not ok


@pytest.mark.parametrize("parent,child", [
    ({"max_amount_usd": float("nan")}, {"max_amount_usd": 5.0}),
    ({"max_amount_usd": 10.0}, {"max_amount_usd": float("nan")}),
    ({"max_amount_usd": float("inf")}, {"max_amount_usd": 5.0}),
    ({"max_amount_usd": 10.0}, {"max_amount_usd": float("inf")}),
    ({}, {"max_amount_usd": float("nan")}),
])
def test_scope_is_subset_rejects_nonfinite_limits(parent, child):
    from kya.delegation import scope_is_subset
    assert scope_is_subset(parent, child) is False
