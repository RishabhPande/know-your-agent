"""Know Your Agent: verifiable agent credentials (v0.1).

An agent credential binds an agent to a human principal, a scope, and a
session window, and is signed with Ed25519. The credential is plain JSON, so
any implementation can produce or check it.

Verification fails closed: any problem yields (False, reason) instead of
raising, except for programmer-level misuse (wrong key types, invalid issue
arguments), which raises immediately so bugs surface during development.

Delegation chains live in delegation.py: a delegated credential carries
``delegated_from`` (the parent credential_id) and ``delegator_agent_id``
(the parent agent_id), and verify_chain() walks the chain enforcing that
scope only narrows and the session window only shrinks.

Revocation management lives in revocation.py: a RevocationList owns the
revoked ids, with a revoke API and JSON persistence. verify_credential
accepts either a plain set of revoked ids or a RevocationList, so a
revoked credential is rejected when the caller supplies either one.

What later iterations still do NOT include:
- an audit trail (a signed append-only log of issuance and verification)

The credential carries a credential_id that serves as the revocation handle
for the revocation list.
"""

import base64
import binascii
import json
import math
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALGORITHM = "Ed25519"
CREDENTIAL_VERSION = 1

# Reason codes returned by verify_credential, in check order.
REASON_OK = "ok"
REASON_MALFORMED = "malformed"
REASON_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_REVOKED = "revoked"
REASON_EXPIRED = "expired"
REASON_NOT_YET_VALID = "not_yet_valid"
REASON_BAD_SCOPE = "bad_scope"


def generate_keypair():
    """Generate a fresh Ed25519 keypair. Returns (private_key, public_key)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_pem(private_key):
    """Serialize a private key to PEM (PKCS8, no encryption)."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def public_key_to_pem(public_key):
    """Serialize a public key to PEM (SubjectPublicKeyInfo)."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_private_key_pem(pem_text):
    """Load a private key from PEM text produced by private_key_to_pem."""
    return serialization.load_pem_private_key(pem_text.encode("ascii"), password=None)


def load_public_key_pem(pem_text):
    """Load a public key from PEM text produced by public_key_to_pem."""
    return serialization.load_pem_public_key(pem_text.encode("ascii"))


def _to_utc_iso(value):
    """Normalize a datetime or ISO 8601 string to a UTC 'Z' string."""
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        return _parse_iso(value).strftime("%Y-%m-%dT%H:%M:%SZ")
    raise TypeError("time value must be a datetime or ISO 8601 string")


def _parse_iso(value):
    """Parse an ISO 8601 string (with Z or offset) to an aware datetime."""
    if not isinstance(value, str):
        raise TypeError("time value must be a string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO 8601 time: %r" % value) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _canonical_bytes(payload):
    """Canonical JSON bytes for signing: sorted keys, no whitespace."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _validate_scope(scope):
    """Validate the scope dict at issuance time. Raises ValueError."""
    if not isinstance(scope, dict):
        raise ValueError("scope must be a dict")
    if "max_amount_usd" in scope:
        amount = scope["max_amount_usd"]
        if not isinstance(amount, (int, float)) or isinstance(amount, bool):
            raise ValueError("scope max_amount_usd must be a number")
        if not math.isfinite(amount):
            raise ValueError("scope max_amount_usd must be finite")
        if amount <= 0:
            raise ValueError("scope max_amount_usd must be positive")
    if "categories" in scope:
        categories = scope["categories"]
        if not isinstance(categories, list) or not all(
            isinstance(c, str) for c in categories
        ):
            raise ValueError("scope categories must be a list of strings")


def issue_credential(
    private_key,
    *,
    agent_id,
    principal,
    scope,
    not_before,
    not_after,
    issuer="kya",
    credential_id=None,
    delegated_from=None,
    delegator_agent_id=None,
):
    """Issue a signed agent credential (a plain JSON-serializable dict).

    Args:
        private_key: Ed25519 private key of the issuer.
        agent_id: identifier of the agent being authorized (non-empty str).
        principal: identifier of the human authorizing the agent (non-empty str).
        scope: dict describing what the agent may do, e.g.
            {"max_amount_usd": 50.0, "categories": ["electronics"]}.
        not_before / not_after: session window, as datetimes or ISO strings.
        issuer: identifier of the issuer (default "kya").
        credential_id: optional id; generated when omitted. This is the
            revocation handle used by RevocationList (see revocation.py).
        delegated_from: optional parent credential_id. When set,
            delegator_agent_id must also be set, and the credential is a
            delegation link; verify_chain() (see delegation.py) is the
            enforcement point for scope/window narrowing. issue_credential
            itself does NOT check narrowing against the parent — that is
            delegate_credential()'s job — so a directly issued link with a
            widened scope is still signed, but verify_chain() rejects it.
        delegator_agent_id: optional parent agent_id; required exactly
            when delegated_from is set.

    Returns:
        dict with keys "payload", "signature" (base64url), "algorithm".
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("agent_id must be a non-empty string")
    if not isinstance(principal, str) or not principal:
        raise ValueError("principal must be a non-empty string")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("issuer must be a non-empty string")
    if (delegated_from is None) != (delegator_agent_id is None):
        raise ValueError(
            "delegated_from and delegator_agent_id must be set together"
        )
    if delegated_from is not None and (
        not isinstance(delegated_from, str) or not delegated_from
    ):
        raise ValueError("delegated_from must be a non-empty string")
    if delegator_agent_id is not None and (
        not isinstance(delegator_agent_id, str) or not delegator_agent_id
    ):
        raise ValueError("delegator_agent_id must be a non-empty string")
    _validate_scope(scope)
    start = _to_utc_iso(not_before)
    end = _to_utc_iso(not_after)
    if _parse_iso(end) <= _parse_iso(start):
        raise ValueError("not_after must be later than not_before")
    payload = {
        "version": CREDENTIAL_VERSION,
        "credential_id": credential_id or uuid.uuid4().hex,
        "agent_id": agent_id,
        "principal": principal,
        "issuer": issuer,
        "scope": scope,
        "not_before": start,
        "not_after": end,
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if delegated_from is not None:
        payload["delegated_from"] = delegated_from
        payload["delegator_agent_id"] = delegator_agent_id
    signature = private_key.sign(_canonical_bytes(payload))
    return {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii"),
        "algorithm": ALGORITHM,
    }


def verify_credential(public_key, credential, *, now=None, revoked_ids=None):
    """Verify a credential. Fails closed: returns (False, reason) on any problem.

    Args:
        public_key: Ed25519 public key of the expected issuer.
        credential: dict produced by issue_credential (or its JSON round-trip).
        now: datetime for the session-window check (defaults to current UTC).
        revoked_ids: optional set of credential_ids treated as revoked,
            or a RevocationList (see revocation.py), which is looked up
            at verification time. A plain set still works exactly as
            before, so existing callers need no changes.

    Returns:
        (True, "ok") or (False, reason) where reason is one of the
        REASON_* codes in this module, in this check order: malformed,
        unsupported algorithm, bad signature, revoked, expired /
        not yet valid, bad scope.
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    if not isinstance(credential, dict):
        return False, REASON_MALFORMED
    payload = credential.get("payload")
    signature_b64 = credential.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature_b64, str):
        return False, REASON_MALFORMED
    if credential.get("algorithm") != ALGORITHM:
        return False, REASON_UNSUPPORTED_ALGORITHM
    try:
        signature = base64.b64decode(
            signature_b64.encode("ascii"), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError):
        return False, REASON_MALFORMED
    try:
        public_key.verify(signature, _canonical_bytes(payload))
    except InvalidSignature:
        return False, REASON_BAD_SIGNATURE
    except Exception:
        return False, REASON_MALFORMED
    if revoked_ids is not None:
        # A RevocationList is accepted directly (duck-typed, to avoid a
        # circular import with revocation.py); anything else is treated
        # as a plain container of ids, as before.
        if callable(getattr(revoked_ids, "revoked_ids", None)):
            revoked_lookup = revoked_ids.revoked_ids()
        else:
            revoked_lookup = revoked_ids
        if payload.get("credential_id") in revoked_lookup:
            return False, REASON_REVOKED
    try:
        start = _parse_iso(payload["not_before"])
        end = _parse_iso(payload["not_after"])
    except (KeyError, TypeError, ValueError):
        return False, REASON_MALFORMED
    check_time = now if now is not None else datetime.now(timezone.utc)
    if check_time.tzinfo is None:
        check_time = check_time.replace(tzinfo=timezone.utc)
    check_time = check_time.astimezone(timezone.utc)
    if check_time > end:
        return False, REASON_EXPIRED
    if check_time < start:
        return False, REASON_NOT_YET_VALID
    if not isinstance(payload.get("scope"), dict):
        return False, REASON_BAD_SCOPE
    # Credentials signed elsewhere never went through issue_credential, so
    # re-check the scope shape (finite, positive limit) at verification time.
    try:
        _validate_scope(payload["scope"])
    except ValueError:
        return False, REASON_BAD_SCOPE
    return True, REASON_OK
