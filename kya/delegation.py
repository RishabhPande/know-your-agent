"""Delegation chains for Know Your Agent credentials.

An agent holding a credential may delegate a *subset* of its authority to a
sub-agent. The delegated credential is a normal signed credential (same
issuer key, same format) plus two link fields in its payload:

- ``delegated_from``: the parent credential's ``credential_id``.
- ``delegator_agent_id``: the parent credential's ``agent_id``.

A chain is an ordered list ``[root, ..., leaf]``. ``verify_chain()`` is the
enforcement point, and it fails closed:

1. Every link must individually pass ``verify_credential()`` (signature,
   session window, revocation, scope shape). A tampered link therefore fails
   with the ordinary reason (e.g. ``bad_signature``) before any chain rule
   is consulted.
2. Links must connect: each link's ``delegated_from`` must equal the
   previous link's ``credential_id``, and its ``delegator_agent_id`` must
   equal the previous link's ``agent_id``; credential_ids must be unique.
   Otherwise ``bad_chain``.
3. The principal and issuer must be identical across the whole chain.
   A principal change is ``principal_mismatch``; an issuer change is
   ``bad_chain`` (the chain is not rooted in one issuer).
4. The session window may only shrink: a link's ``not_before`` must be no
   earlier than its parent's, and its ``not_after`` no later than its
   parent's. Otherwise ``window_widened``.
5. Scope may only narrow, never widen (see ``scope_is_subset()``).
   Otherwise ``scope_widened``.

``delegate_credential()`` is the safe constructor: it checks rules 4 and 5
up front and raises ``ValueError`` on any widening, so a well-behaved
delegator never produces a chain that ``verify_chain()`` rejects. It does
*not* verify the parent's signature — the caller is expected to have
verified the parent (or the chain so far) before delegating from it, and
``verify_chain()`` re-checks every signature anyway.

Scope-narrowing semantics (purchase scope, the only scope shape v0.1
defines; see credentials._validate_scope):

- ``max_amount_usd``: absent means unbounded. A child value must be
  present and <= the parent value when the parent has one; when the parent
  has none, any child value (or none) is a narrowing-or-equal.
- ``categories``: absent means unrestricted. A child list must be a
  subset of the parent list when the parent has one; when the parent has
  none, any child list (or none) is a narrowing-or-equal.
- Any other scope key: the child must not introduce a key the parent
  lacks, and must keep the parent's value unchanged. Unknown capabilities
  are never widened by delegation, fail-closed.

A single (non-delegated) credential is a valid chain of length one, and
``verify_chain()`` accepts it — provided it carries no delegation link
fields. A lone credential that *does* carry link fields is ``bad_chain``:
its parent is missing from the chain.
"""

from .credentials import (
    REASON_BAD_SCOPE,
    REASON_MALFORMED,
    _parse_iso,
    _to_utc_iso,
    _validate_scope,
    issue_credential,
    verify_credential,
)
from .policy import check_purchase

REASON_BAD_CHAIN = "bad_chain"
REASON_SCOPE_WIDENED = "scope_widened"
REASON_WINDOW_WIDENED = "window_widened"
REASON_PRINCIPAL_MISMATCH = "principal_mismatch"


def scope_is_subset(parent_scope, child_scope):
    """Return True iff child_scope narrows (or equals) parent_scope.

    Both scopes must be dicts; anything else is not a subset. See the
    module docstring for the per-key semantics. This is a pure scope
    comparison — it does not check signatures, windows, or principals.
    """
    if not isinstance(parent_scope, dict) or not isinstance(child_scope, dict):
        return False
    # max_amount_usd: absent = unbounded.
    parent_max = parent_scope.get("max_amount_usd")
    child_max = child_scope.get("max_amount_usd")
    if parent_max is not None:
        if child_max is None or child_max > parent_max:
            return False
    # categories: absent = unrestricted.
    parent_cats = parent_scope.get("categories")
    child_cats = child_scope.get("categories")
    if parent_cats is not None:
        if child_cats is None or not set(child_cats) <= set(parent_cats):
            return False
    # Unknown keys: no new keys, no changed values.
    known = {"max_amount_usd", "categories"}
    for key, value in child_scope.items():
        if key in known:
            continue
        if key not in parent_scope or parent_scope[key] != value:
            return False
    return True


def window_is_subset(parent_payload, child_payload):
    """Return True iff the child's session window sits inside the parent's."""
    try:
        parent_start = _parse_iso(parent_payload["not_before"])
        parent_end = _parse_iso(parent_payload["not_after"])
        child_start = _parse_iso(child_payload["not_before"])
        child_end = _parse_iso(child_payload["not_after"])
    except (KeyError, TypeError, ValueError):
        return False
    return child_start >= parent_start and child_end <= parent_end


def delegate_credential(
    private_key,
    parent_credential,
    *,
    agent_id,
    scope,
    not_before,
    not_after,
    credential_id=None,
):
    """Delegate a subset of a parent credential to a sub-agent.

    Args:
        private_key: Ed25519 private key of the issuer (same issuer as
            the parent credential).
        parent_credential: dict produced by issue_credential (or
            delegate_credential). Its payload supplies the principal,
            issuer, and the bounds the delegation must stay inside.
        agent_id: identifier of the sub-agent (non-empty str).
        scope: the sub-agent's scope; must narrow the parent scope.
        not_before / not_after: the sub-agent's session window; must
            sit inside the parent window.
        credential_id: optional id; generated when omitted.

    Raises ValueError on a malformed parent, a widened scope, or a
    widened window. The returned credential's payload carries
    ``delegated_from`` and ``delegator_agent_id`` linking it to the
    parent, and inherits the parent's principal and issuer.
    """
    if not isinstance(parent_credential, dict):
        raise ValueError("parent_credential must be a credential dict")
    parent_payload = parent_credential.get("payload")
    if not isinstance(parent_payload, dict):
        raise ValueError("parent_credential has no payload")
    _validate_scope(scope)
    parent_scope = parent_payload.get("scope")
    if not isinstance(parent_scope, dict):
        raise ValueError("parent credential has no scope to delegate from")
    if not scope_is_subset(parent_scope, scope):
        raise ValueError("delegated scope must narrow the parent scope")
    child_start = _to_utc_iso(not_before)
    child_end = _to_utc_iso(not_after)
    try:
        parent_start = _to_utc_iso(parent_payload["not_before"])
        parent_end = _to_utc_iso(parent_payload["not_after"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("parent credential has an invalid session window") from exc
    if _parse_iso(child_start) < _parse_iso(parent_start) or _parse_iso(
        child_end
    ) > _parse_iso(parent_end):
        raise ValueError("delegated session window must sit inside the parent window")
    principal = parent_payload.get("principal")
    issuer = parent_payload.get("issuer")
    if not isinstance(principal, str) or not principal:
        raise ValueError("parent credential has no principal")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("parent credential has no issuer")
    return issue_credential(
        private_key,
        agent_id=agent_id,
        principal=principal,
        scope=scope,
        not_before=child_start,
        not_after=child_end,
        issuer=issuer,
        credential_id=credential_id,
        delegated_from=parent_payload.get("credential_id"),
        delegator_agent_id=parent_payload.get("agent_id"),
    )


def verify_chain(public_key, chain, *, now=None, revoked_ids=None):
    """Verify a delegation chain. Fails closed.

    Args:
        public_key: Ed25519 public key of the issuer.
        chain: ordered list [root, ..., leaf] of credential dicts.
        now, revoked_ids: passed through to verify_credential for
            every link, so a RevocationList (or a plain set of ids)
            revokes any link in the chain, root or leaf.

    Returns (True, "ok") or (False, reason). Individual-link failures
    (bad_signature, revoked, expired, ...) are reported first, in chain
    order; structural failures then follow in this order: bad_chain
    (linkage / issuer / lone link), principal_mismatch, window_widened,
    scope_widened.
    """
    if not isinstance(chain, (list, tuple)) or not chain:
        return False, REASON_MALFORMED
    if any(not isinstance(link, dict) for link in chain):
        return False, REASON_MALFORMED
    # 1. Every link must verify on its own.
    for link in chain:
        ok, reason = verify_credential(
            public_key, link, now=now, revoked_ids=revoked_ids
        )
        if not ok:
            return False, reason
    payloads = [link["payload"] for link in chain]
    # A lone link must not claim a parent that is not in the chain.
    if len(payloads) == 1 and (
        "delegated_from" in payloads[0] or "delegator_agent_id" in payloads[0]
    ):
        return False, REASON_BAD_CHAIN
    # 2. Linkage, uniqueness, single issuer.
    seen_ids = set()
    for payload in payloads:
        credential_id = payload.get("credential_id")
        if credential_id in seen_ids:
            return False, REASON_BAD_CHAIN
        seen_ids.add(credential_id)
    root = payloads[0]
    if "delegated_from" in root or "delegator_agent_id" in root:
        return False, REASON_BAD_CHAIN
    for parent, child in zip(payloads, payloads[1:]):
        if child.get("delegated_from") != parent.get("credential_id"):
            return False, REASON_BAD_CHAIN
        if child.get("delegator_agent_id") != parent.get("agent_id"):
            return False, REASON_BAD_CHAIN
        if child.get("issuer") != root.get("issuer"):
            return False, REASON_BAD_CHAIN
    # 3. One principal throughout.
    for payload in payloads[1:]:
        if payload.get("principal") != root.get("principal"):
            return False, REASON_PRINCIPAL_MISMATCH
    # 4. Windows only shrink.
    for parent, child in zip(payloads, payloads[1:]):
        if not window_is_subset(parent, child):
            return False, REASON_WINDOW_WIDENED
    # 5. Scopes only narrow.
    for parent, child in zip(payloads, payloads[1:]):
        if not isinstance(parent.get("scope"), dict) or not isinstance(
            child.get("scope"), dict
        ):
            return False, REASON_BAD_SCOPE
        if not scope_is_subset(parent["scope"], child["scope"]):
            return False, REASON_SCOPE_WIDENED
    return True, "ok"


def authorize_purchase_chain(
    public_key, chain, amount_usd, category, **verify_kwargs
):
    """Verify a chain and check a purchase against its leaf scope.

    Returns (True, "allowed") only when the whole chain verifies AND
    the purchase is inside the leaf credential's scope. Otherwise the
    chain reason (e.g. "scope_widened", "revoked") or a purchase-scope
    reason (e.g. "amount_exceeds_scope"). An empty chain is "malformed".
    """
    if not isinstance(chain, (list, tuple)) or not chain:
        return False, REASON_MALFORMED
    ok, reason = verify_chain(public_key, chain, **verify_kwargs)
    if not ok:
        return False, reason
    return check_purchase(chain[-1]["payload"], amount_usd, category)
