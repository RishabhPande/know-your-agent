"""Audit trail for Know Your Agent credentials.

A disputed transaction raises a question no single verification can answer
after the fact: what happened, in what order, and can anyone prove the
record was not rewritten since? ``AuditLog`` is that record.

Each entry is one event: an issuance, a verification, or a revocation.
Entries form a hash chain and each entry is signed with Ed25519, so the
log can be checked by anyone holding the auditor's public key:

- ``prev_hash`` links an entry to the one before it (the first entry
  links to a genesis hash of 64 zeroes). Inserting, deleting, or
  reordering an entry in the middle breaks every later link.
- ``entry_hash`` is the SHA-256 of the entry's canonical content
  (everything except ``entry_hash`` and ``signature``). Changing any
  field of an entry changes its hash and breaks the chain.
- ``signature`` is an Ed25519 signature over the canonical content plus
  the entry hash, made with the auditor's private key. A verifier with
  the matching public key can confirm who recorded the entry.

Verification is fail closed and returns ``(False, reason)`` instead of
raising on a bad log, mirroring ``verify_credential``. Reasons, in check
order: ``malformed``, ``bad_index``, ``bad_hash_chain``,
``bad_signature``. Loading a log (``from_dict`` / ``from_json``) checks
shape only, never signatures; call ``verify`` separately before trusting
a loaded log.

Honest limits, stated plainly because they decide how much this log
proves:

- Dropping entries from the *tail* still verifies: a shorter chain is
  still a valid chain. The defense is an external anchor: publish the
  latest ``entry_hash`` somewhere the auditor cannot rewrite (a
  timestamped post, a second store, a periodic commit) and pass it as
  ``expected_last_hash`` to ``verify``. A truncated log then fails,
  because its last hash is not the anchored one.
- The log records what the caller claims happened. It does not prove a
  verification really ran; a caller that never records an event leaves
  no trace of it. The log proves the recorded history was not altered,
  not that the history is complete.
- The auditor's key is the trust root. In the demo the issuer key signs
  the log for simplicity; a real deployment should use a separate audit
  key held by whoever must answer for the record, not by the issuer.

Entries are JSON-serializable, so a log can be saved to disk and loaded
back with ``to_json`` / ``from_json``. Loading validates strictly and
raises ``ValueError`` on anything malformed, instead of silently
dropping entries. The log is append-only by construction: there is no
delete, truncate, or edit method, and ``entries()`` returns copies, so
mutating a returned entry never changes the log.

Entry kinds are exactly ``issued``, ``verified``, and ``revoked``.
``outcome`` is ``issued`` / ``revoked`` for those kinds, and the
verification reason (``ok`` or a failure reason such as
``bad_signature``) for ``verified`` entries. ``detail`` is an optional
dict for extra context (for example a purchase amount, or the ids of a
delegation chain); it is part of the signed content, so it cannot be
edited after the fact either.
"""

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .credentials import _canonical_bytes, _to_utc_iso

AUDIT_LOG_VERSION = 1
AUDIT_GENESIS_HASH = "0" * 64

KIND_ISSUED = "issued"
KIND_VERIFIED = "verified"
KIND_REVOKED = "revoked"
AUDIT_KINDS = (KIND_ISSUED, KIND_VERIFIED, KIND_REVOKED)

AUDIT_OK = "ok"
AUDIT_MALFORMED = "malformed"
AUDIT_BAD_INDEX = "bad_index"
AUDIT_BAD_HASH_CHAIN = "bad_hash_chain"
AUDIT_BAD_SIGNATURE = "bad_signature"


def _validate_credential_id(credential_id):
    if not isinstance(credential_id, str) or not credential_id:
        raise ValueError("credential_id must be a non-empty string")


def _validate_entry_shape(entry):
    """Validate one entry dict and return a normalized copy.

    Checks types and formats, plus the entry-hash format. It does NOT
    check the hash value, the chain linkage, or the signature; that is
    verify's job. Raises ValueError on anything malformed.
    """
    if not isinstance(entry, dict):
        raise ValueError("audit entry must be a dict")
    index = entry.get("index")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("audit entry index must be a non-negative integer")
    kind = entry.get("kind")
    if kind not in AUDIT_KINDS:
        raise ValueError("audit entry kind must be one of %r" % (AUDIT_KINDS,))
    _validate_credential_id(entry.get("credential_id"))
    for field in ("agent_id", "principal", "outcome"):
        value = entry.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError("audit entry %s must be a non-empty string" % field)
    recorded_at = entry.get("recorded_at")
    if not isinstance(recorded_at, str):
        raise ValueError("audit entry recorded_at must be an ISO 8601 string")
    try:
        normalized_at = _to_utc_iso(recorded_at)
    except (TypeError, ValueError) as exc:
        raise ValueError("audit entry recorded_at is not a valid time") from exc
    detail = entry.get("detail")
    if not isinstance(detail, dict):
        raise ValueError("audit entry detail must be a dict")
    try:
        _canonical_bytes(detail)
    except (TypeError, ValueError) as exc:
        raise ValueError("audit entry detail must be JSON-serializable") from exc
    prev_hash = entry.get("prev_hash")
    if (
        not isinstance(prev_hash, str)
        or len(prev_hash) != 64
        or any(c not in "0123456789abcdef" for c in prev_hash)
    ):
        raise ValueError("audit entry prev_hash must be a 64-hex-char hash")
    entry_hash = entry.get("entry_hash")
    if (
        not isinstance(entry_hash, str)
        or len(entry_hash) != 64
        or any(c not in "0123456789abcdef" for c in entry_hash)
    ):
        raise ValueError("audit entry entry_hash must be a 64-hex-char hash")
    signature = entry.get("signature")
    if not isinstance(signature, str) or not signature:
        raise ValueError("audit entry signature must be a non-empty string")
    try:
        base64.b64decode(signature.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("audit entry signature must be base64url") from exc
    return {
        "index": index,
        "kind": kind,
        "credential_id": entry["credential_id"],
        "agent_id": entry["agent_id"],
        "principal": entry["principal"],
        "outcome": entry["outcome"],
        "detail": dict(detail),
        "recorded_at": normalized_at,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "signature": signature,
    }


def _entry_content(entry):
    """The signed content of an entry: everything except hash and signature."""
    return {
        "index": entry["index"],
        "kind": entry["kind"],
        "credential_id": entry["credential_id"],
        "agent_id": entry["agent_id"],
        "principal": entry["principal"],
        "outcome": entry["outcome"],
        "detail": entry["detail"],
        "recorded_at": entry["recorded_at"],
        "prev_hash": entry["prev_hash"],
    }


def _compute_entry_hash(content):
    return hashlib.sha256(_canonical_bytes(content)).hexdigest()


def _signed_bytes(content, entry_hash):
    """Bytes the auditor signs: content plus its hash, canonically encoded."""
    return _canonical_bytes(dict(content, entry_hash=entry_hash))


def verify_audit_entries(public_key, entries, *, expected_last_hash=None):
    """Verify a list of audit entries. Fails closed.

    Args:
        public_key: Ed25519 public key of the auditor.
        entries: list of entry dicts, in log order.
        expected_last_hash: optional external anchor (see module
            docstring). When given, the last entry's hash must equal it.

    Returns (True, "ok") or (False, reason) with reason in check order:
    malformed, bad_index, bad_hash_chain, bad_signature. An empty log
    verifies, but fails when an anchor is expected and no entry exists.
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    if not isinstance(entries, (list, tuple)):
        return False, AUDIT_MALFORMED
    parsed = []
    for entry in entries:
        try:
            parsed.append(_validate_entry_shape(entry))
        except ValueError:
            return False, AUDIT_MALFORMED
    expected_prev = AUDIT_GENESIS_HASH
    for position, entry in enumerate(parsed):
        if entry["index"] != position:
            return False, AUDIT_BAD_INDEX
        if entry["prev_hash"] != expected_prev:
            return False, AUDIT_BAD_HASH_CHAIN
        content = _entry_content(entry)
        if _compute_entry_hash(content) != entry["entry_hash"]:
            return False, AUDIT_BAD_HASH_CHAIN
        try:
            signature = base64.b64decode(
                entry["signature"].encode("ascii"), altchars=b"-_", validate=True
            )
            public_key.verify(
                signature, _signed_bytes(content, entry["entry_hash"])
            )
        except InvalidSignature:
            return False, AUDIT_BAD_SIGNATURE
        except Exception:
            return False, AUDIT_MALFORMED
        expected_prev = entry["entry_hash"]
    if expected_last_hash is not None:
        last_hash = parsed[-1]["entry_hash"] if parsed else None
        if last_hash != expected_last_hash:
            return False, AUDIT_BAD_HASH_CHAIN
    return True, AUDIT_OK


class AuditLog:
    """A signed, append-only audit log of credential events.

    Create with the auditor's private key to record events, or without
    one to hold a loaded log for verification only: appending to a
    keyless log raises ValueError.
    """

    def __init__(self, private_key=None, entries=None):
        """Create an empty log, or one preloaded from entry dicts.

        Args:
            private_key: optional Ed25519 private key of the auditor.
                Required for appending; omit for a verification-only log.
            entries: optional iterable of entry dicts in ``to_dict``
                format. Indices must run 0, 1, 2, ... and prev_hash
                links must already chain, or ValueError is raised.
                Signatures are NOT checked here; call ``verify`` for
                that after loading.
        """
        if private_key is not None and not isinstance(
            private_key, Ed25519PrivateKey
        ):
            raise TypeError("private_key must be an Ed25519PrivateKey or None")
        self._private_key = private_key
        self._entries = []
        if entries is not None:
            parsed = [_validate_entry_shape(entry) for entry in entries]
            expected_prev = AUDIT_GENESIS_HASH
            for position, entry in enumerate(parsed):
                if entry["index"] != position:
                    raise ValueError(
                        "audit entries must be indexed 0, 1, 2, ... in order"
                    )
                if entry["prev_hash"] != expected_prev:
                    raise ValueError(
                        "audit entries do not chain: entry %d has the wrong "
                        "prev_hash" % position
                    )
                expected_prev = entry["entry_hash"]
            self._entries = parsed

    def append(
        self,
        kind,
        credential_id,
        *,
        agent_id,
        principal,
        outcome,
        detail=None,
        recorded_at=None,
    ):
        """Append one signed entry. Returns a copy of the new entry.

        Raises ValueError on a bad kind, id, field, detail, or time,
        and when this log has no signing key.
        """
        if self._private_key is None:
            raise ValueError("audit log has no signing key; cannot append")
        if kind not in AUDIT_KINDS:
            raise ValueError("audit entry kind must be one of %r" % (AUDIT_KINDS,))
        _validate_credential_id(credential_id)
        for field, value in (
            ("agent_id", agent_id),
            ("principal", principal),
            ("outcome", outcome),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError("audit entry %s must be a non-empty string" % field)
        if detail is None:
            detail = {}
        if not isinstance(detail, dict):
            raise ValueError("audit entry detail must be a dict")
        try:
            _canonical_bytes(detail)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "audit entry detail must be JSON-serializable"
            ) from exc
        if recorded_at is None:
            normalized_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            try:
                normalized_at = _to_utc_iso(recorded_at)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "recorded_at must be a datetime or ISO 8601 string"
                ) from exc
        prev_hash = (
            self._entries[-1]["entry_hash"] if self._entries else AUDIT_GENESIS_HASH
        )
        content = {
            "index": len(self._entries),
            "kind": kind,
            "credential_id": credential_id,
            "agent_id": agent_id,
            "principal": principal,
            "outcome": outcome,
            "detail": dict(detail),
            "recorded_at": normalized_at,
            "prev_hash": prev_hash,
        }
        entry_hash = _compute_entry_hash(content)
        signature = self._private_key.sign(_signed_bytes(content, entry_hash))
        entry = dict(
            content,
            entry_hash=entry_hash,
            signature=base64.urlsafe_b64encode(signature).decode("ascii"),
        )
        self._entries.append(entry)
        return dict(entry, detail=dict(entry["detail"]))

    def record_issued(self, credential, *, detail=None, recorded_at=None):
        """Append an ``issued`` entry for a credential dict.

        Raises ValueError when the credential is malformed or carries
        no usable agent, principal, or credential_id.
        """
        payload = _payload_of(credential)
        return self.append(
            KIND_ISSUED,
            payload["credential_id"],
            agent_id=payload["agent_id"],
            principal=payload["principal"],
            outcome=KIND_ISSUED,
            detail=detail,
            recorded_at=recorded_at,
        )

    def record_verified(
        self, credential, ok, reason, *, detail=None, recorded_at=None
    ):
        """Append a ``verified`` entry for a credential dict.

        ``ok`` and ``reason`` are the pair ``verify_credential`` (or
        ``verify_chain``) returned; ``outcome`` stores ``ok`` on
        success and the failure reason otherwise. Raises ValueError on
        a malformed credential or a bad reason.
        """
        if not isinstance(reason, str) or not reason:
            raise ValueError("verification reason must be a non-empty string")
        payload = _payload_of(credential)
        return self.append(
            KIND_VERIFIED,
            payload["credential_id"],
            agent_id=payload["agent_id"],
            principal=payload["principal"],
            outcome="ok" if ok else reason,
            detail=detail,
            recorded_at=recorded_at,
        )

    def record_revoked(self, credential, *, reason=None, detail=None, recorded_at=None):
        """Append a ``revoked`` entry for a credential dict.

        Agent and principal come from the credential payload, and an
        optional ``reason`` is stored inside ``detail`` (merged with any
        caller-supplied detail keys). A bare credential id is not
        enough on its own: it names no agent or principal, so callers
        revoking by id should use ``append`` with those fields given
        explicitly. Raises ValueError on a malformed credential or a
        non-string reason.
        """
        if reason is not None and not isinstance(reason, str):
            raise ValueError("revocation reason must be a string or None")
        payload = _payload_of(credential)
        merged = dict(detail) if detail is not None else {}
        if reason is not None:
            merged["reason"] = reason
        return self.append(
            KIND_REVOKED,
            payload["credential_id"],
            agent_id=payload["agent_id"],
            principal=payload["principal"],
            outcome=KIND_REVOKED,
            detail=merged,
            recorded_at=recorded_at,
        )

    def __len__(self):
        return len(self._entries)

    def __iter__(self):
        return iter(self.entries())

    def entries(self):
        """Return copies of all entries, in log order."""
        return [dict(entry, detail=dict(entry["detail"])) for entry in self._entries]

    def get(self, index):
        """Return a copy of the entry at index, or None when out of range."""
        if not isinstance(index, int) or isinstance(index, bool):
            return None
        if index < 0 or index >= len(self._entries):
            return None
        entry = self._entries[index]
        return dict(entry, detail=dict(entry["detail"]))

    @property
    def last_hash(self):
        """The entry_hash of the latest entry, or the genesis hash when empty."""
        if not self._entries:
            return AUDIT_GENESIS_HASH
        return self._entries[-1]["entry_hash"]

    def verify(self, public_key, *, expected_last_hash=None):
        """Verify this log against the auditor's public key.

        Returns (True, "ok") or (False, reason); see
        ``verify_audit_entries`` for the reason codes and check order.
        """
        return verify_audit_entries(
            public_key, self._entries, expected_last_hash=expected_last_hash
        )

    def to_dict(self):
        """Serialize to a plain JSON-serializable dict."""
        return {
            "version": AUDIT_LOG_VERSION,
            "entries": self.entries(),
        }

    @classmethod
    def from_dict(cls, data, private_key=None):
        """Load a log from ``to_dict`` output. Raises ValueError if malformed.

        ``private_key`` is optional: pass it when the loaded log should
        keep accepting new entries; omit it for a verification-only log.
        """
        if not isinstance(data, dict):
            raise ValueError("audit log data must be a dict")
        if data.get("version") != AUDIT_LOG_VERSION:
            raise ValueError(
                "unsupported audit log version: %r" % (data.get("version"),)
            )
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise ValueError("audit log entries must be a list")
        return cls(private_key, entries)

    def to_json(self):
        """Serialize to a JSON string (sorted keys, no extra whitespace)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, text, private_key=None):
        """Load a log from ``to_json`` output. Raises ValueError if malformed."""
        if not isinstance(text, str):
            raise ValueError("audit log JSON must be a string")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid audit log JSON") from exc
        return cls.from_dict(data, private_key)


def _payload_of(credential):
    """Pull a validated payload out of a credential dict, or raise ValueError."""
    if not isinstance(credential, dict):
        raise ValueError("credential must be a credential dict")
    payload = credential.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("credential has no payload")
    for field in ("credential_id", "agent_id", "principal"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError("credential payload has no usable %s" % field)
    return payload
