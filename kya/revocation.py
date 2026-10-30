"""Revocation management for Know Your Agent credentials.

Before this module, verification accepted a caller-managed set of revoked
credential ids (see ``verify_credential(..., revoked_ids=...)``). That set
worked, but nothing owned it: nothing recorded when a revocation happened,
nothing stopped a caller from mutating it by accident, and nothing survived
a process restart. ``RevocationList`` is that owner.

A revocation is permanent in this store. There is no unrevoke: once an id
is revoked, every later verification of that credential fails with
``revoked``, even inside its session window. If a revocation was a mistake,
issue a fresh credential instead of trying to resurrect the old one. That
rule is what makes a revocation list safe to hand to a verifier without
a second thought.

The store plugs into verification two ways, both fail closed:

1. Pass the store itself as ``revoked_ids`` to ``verify_credential``,
   ``verify_chain``, ``authorize_purchase``, or
   ``authorize_purchase_chain``. Those functions accept a ``RevocationList``
   (duck-typed: anything with a callable ``revoked_ids`` method) as well
   as a plain set of ids, so existing callers keep working unchanged.
2. Call ``store.revoked_ids()`` yourself and pass the returned set.

Entries are JSON-serializable, so a list can be saved to disk and loaded
back with ``to_json`` / ``from_json`` (or ``to_dict`` / ``from_dict``).
Loading validates strictly and raises ``ValueError`` on anything
malformed, duplicated, or from an unknown format version, rather than
silently dropping entries.
"""

import json
from datetime import datetime, timezone

from .credentials import _to_utc_iso

REVOCATION_LIST_VERSION = 1


def _validate_credential_id(credential_id):
    if not isinstance(credential_id, str) or not credential_id:
        raise ValueError("credential_id must be a non-empty string")


class RevocationList:
    """A maintained, permanent list of revoked credential ids.

    Each entry records the revoked ``credential_id``, the UTC time it was
    revoked, and an optional human-readable reason (for example
    "reported stolen" or "agent decommissioned"). The reason is bookkeeping
    only; it never affects verification.
    """

    def __init__(self, entries=None):
        """Create an empty list, or one preloaded from entry dicts.

        Args:
            entries: optional iterable of entry dicts in ``to_dict``
                format. Each entry must carry a non-empty
                ``credential_id``; ``revoked_at`` and ``reason`` are
                validated the same way ``from_dict`` validates them.
                Duplicate ids raise ``ValueError``.
        """
        self._entries = {}
        if entries is not None:
            for entry in entries:
                parsed = self._parse_entry(entry)
                credential_id = parsed["credential_id"]
                if credential_id in self._entries:
                    raise ValueError(
                        "duplicate credential_id in revocation entries: %r"
                        % credential_id
                    )
                self._entries[credential_id] = parsed

    @staticmethod
    def _parse_entry(entry):
        """Validate one entry dict and return a normalized copy."""
        if not isinstance(entry, dict):
            raise ValueError("revocation entry must be a dict")
        credential_id = entry.get("credential_id")
        _validate_credential_id(credential_id)
        revoked_at = entry.get("revoked_at")
        if revoked_at is None:
            normalized_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            try:
                normalized_at = _to_utc_iso(revoked_at)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "revocation entry has an invalid revoked_at"
                ) from exc
        reason = entry.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("revocation reason must be a string or None")
        return {
            "credential_id": credential_id,
            "revoked_at": normalized_at,
            "reason": reason,
        }

    def revoke(self, credential_id, *, reason=None, revoked_at=None):
        """Revoke a credential id. Returns True when newly revoked.

        Revoking an already revoked id is a no-op that returns False and
        keeps the original entry (its original time and reason). That
        keeps repeated revocation calls idempotent instead of rewriting
        history. Raises ``ValueError`` on an invalid id, reason, or time.
        """
        _validate_credential_id(credential_id)
        if reason is not None and not isinstance(reason, str):
            raise ValueError("revocation reason must be a string or None")
        if credential_id in self._entries:
            return False
        if revoked_at is None:
            normalized_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            try:
                normalized_at = _to_utc_iso(revoked_at)
            except (TypeError, ValueError) as exc:
                raise ValueError("revoked_at must be a datetime or ISO 8601 string") from exc
        self._entries[credential_id] = {
            "credential_id": credential_id,
            "revoked_at": normalized_at,
            "reason": reason,
        }
        return True

    def revoke_credential(self, credential, *, reason=None, revoked_at=None):
        """Revoke a credential dict by its payload credential_id.

        This is ``revoke()`` with the id pulled out of the credential, so
        callers never have to dig into the payload themselves. Raises
        ``ValueError`` when the credential is malformed or carries no
        usable credential_id.
        """
        if not isinstance(credential, dict):
            raise ValueError("credential must be a credential dict")
        payload = credential.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("credential has no payload")
        credential_id = payload.get("credential_id")
        _validate_credential_id(credential_id)
        return self.revoke(credential_id, reason=reason, revoked_at=revoked_at)

    def is_revoked(self, credential_id):
        """Return True iff the id is on this list. Non-strings are not revoked."""
        return isinstance(credential_id, str) and credential_id in self._entries

    def __contains__(self, credential_id):
        return self.is_revoked(credential_id)

    def __len__(self):
        return len(self._entries)

    def revoked_ids(self):
        """Return the revoked ids as a fresh set.

        The returned set is a copy: mutating it never changes the store.
        It is also what ``verify_credential(..., revoked_ids=...)`` accepts
        directly, for callers that prefer passing a plain set.
        """
        return set(self._entries)

    def get(self, credential_id):
        """Return a copy of the entry for an id, or None when not revoked."""
        entry = self._entries.get(credential_id)
        return dict(entry) if entry is not None else None

    def entries(self):
        """Return copies of all entries, in revocation order."""
        return [dict(entry) for entry in self._entries.values()]

    def to_dict(self):
        """Serialize to a plain JSON-serializable dict."""
        return {
            "version": REVOCATION_LIST_VERSION,
            "entries": self.entries(),
        }

    @classmethod
    def from_dict(cls, data):
        """Load a list from ``to_dict`` output. Raises ValueError if malformed."""
        if not isinstance(data, dict):
            raise ValueError("revocation list data must be a dict")
        if data.get("version") != REVOCATION_LIST_VERSION:
            raise ValueError(
                "unsupported revocation list version: %r" % (data.get("version"),)
            )
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise ValueError("revocation list entries must be a list")
        return cls(entries)

    def to_json(self):
        """Serialize to a JSON string (sorted keys, no extra whitespace)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, text):
        """Load a list from ``to_json`` output. Raises ValueError if malformed."""
        if not isinstance(text, str):
            raise ValueError("revocation list JSON must be a string")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid revocation list JSON") from exc
        return cls.from_dict(data)
