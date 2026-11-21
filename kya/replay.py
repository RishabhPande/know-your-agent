"""Replay protection for Know Your Agent purchase authorization.

Until now a credential was a bearer presentation: anyone holding a copy
of a genuine credential could present it again inside its session
window and the gate accepted it again, because nothing in the
credential or the gate distinguished a first presentation from a
repeat. The seeded corpus measures that gap directly: its
``attack_replay_in_window`` class replays genuine presentations and,
without replay protection, every one of them is accepted (100 missed
attacks on the default corpus).

This module closes the gap the way payment APIs close it, with an
idempotency key. Each purchase presentation carries a caller-chosen
``presentation_id``: a value the presenting side generates fresh for
each distinct purchase (a UUID is the obvious choice) and reuses only
when it is genuinely retrying the same purchase. ``ReplayStore``
remembers which (credential_id, presentation_id) pairs it has already
authorized. The first authorized presentation records the pair; a
second presentation of the same pair under the same credential is
rejected with ``replay``.

Design rules, all fail closed:

1. Only a successful authorization consumes a presentation id. A
   purchase that fails verification or scope checks records nothing,
   so a rejected attempt cannot burn an id, and an attacker who
   presents someone else's id with a bad credential cannot lock the
   genuine holder out.
2. Plain verification never consumes an id. ``verify_credential`` is a
   question, not a presentation; asking it twice is legitimate. Only
   the purchase authorizers (``authorize_purchase`` and
   ``authorize_purchase_chain``) consult the store, and only when the
   caller passes one.
3. Passing a store without a presentation id is a rejection, not a
   silent skip: when a caller opts into replay protection, a
   presentation that carries no id cannot be checked, so it fails
   with ``missing_presentation_id``.
4. The same presentation id under a different credential is a
   different presentation. Ids only have to be unique per credential,
   so two agents may both use "order-1" without colliding.
5. A chain presentation is keyed by its leaf credential id: the leaf
   is the credential actually being spent.

Entries are JSON-serializable, so a store can be saved and loaded back
with ``to_json`` / ``from_json`` (or ``to_dict`` / ``from_dict``), the
same way ``RevocationList`` persists. Loading validates strictly and
raises ``ValueError`` on anything malformed, duplicated, or from an
unknown format version, rather than silently dropping entries: a store
that quietly forgot a seen presentation would reopen the replay hole
without anyone noticing.

Operations on a shared store are protected by an in-process lock.
Concurrent threads cannot both record the same new presentation, and
entry snapshots and pruning use that same lock.

One honest limit: the store only knows what it has seen. Two merchant
processes that do not share a store do not share replay state, so a
replay aimed at a different process than the original presentation
still passes. A real deployment needs one shared store (or one store
per merchant that the credential is scoped to). Entries also need to
live at least as long as the credential they guard can still be
presented; ``prune`` drops entries first seen before a caller-chosen
cutoff, and pruning too aggressively reopens the hole for credentials
that are still inside their session window.
"""

import json
from datetime import datetime, timezone
from threading import Lock

from .credentials import REASON_MALFORMED, _to_utc_iso

REPLAY_STORE_VERSION = 1

REASON_REPLAY = "replay"
REASON_MISSING_PRESENTATION_ID = "missing_presentation_id"


def _unique_json_object(pairs):
    """Reject duplicate keys before they can replace replay data."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate replay JSON key: %r" % key)
        result[key] = value
    return result


def _validate_id(value, field):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % field)


def _normalize_time(value, field):
    if value is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        return _to_utc_iso(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "%s must be a datetime or ISO 8601 string" % field
        ) from exc


class ReplayStore:
    """A maintained record of purchase presentations already authorized.

    Each entry records the ``credential_id`` that was spent, the
    ``presentation_id`` it was spent under, and the UTC time the store
    first authorized that pair. The pair is the identity of a
    presentation: the same pair seen twice is a replay.
    """

    def __init__(self, entries=None):
        """Create an empty store, or one preloaded from entry dicts.

        Args:
            entries: optional iterable of entry dicts in ``to_dict``
                format. Each entry must carry a non-empty
                ``credential_id`` and ``presentation_id``; ``seen_at``
                is validated the same way ``from_dict`` validates it.
                Duplicate pairs raise ``ValueError``.
        """
        self._entries = {}
        self._lock = Lock()
        if entries is not None:
            for entry in entries:
                parsed = self._parse_entry(entry)
                key = (parsed["credential_id"], parsed["presentation_id"])
                if key in self._entries:
                    raise ValueError(
                        "duplicate presentation in replay entries: %r" % (key,)
                    )
                self._entries[key] = parsed

    @staticmethod
    def _parse_entry(entry):
        """Validate one entry dict and return a normalized copy."""
        if not isinstance(entry, dict):
            raise ValueError("replay entry must be a dict")
        credential_id = entry.get("credential_id")
        _validate_id(credential_id, "credential_id")
        presentation_id = entry.get("presentation_id")
        _validate_id(presentation_id, "presentation_id")
        return {
            "credential_id": credential_id,
            "presentation_id": presentation_id,
            "seen_at": _normalize_time(entry.get("seen_at"), "seen_at"),
        }

    def check_and_record(self, credential_id, presentation_id, *, seen_at=None):
        """Record a presentation. Returns True when it is new.

        The first call for a (credential_id, presentation_id) pair
        records it and returns True. A later call for the same pair
        returns False and keeps the original entry, so a replay never
        rewrites the record of when the presentation was first spent.
        Raises ``ValueError`` on an invalid id or time.

        Callers must only call this for a presentation they are about
        to accept: recording a presentation that is then rejected
        would burn its id (see the module docstring, rule 1).
        """
        _validate_id(credential_id, "credential_id")
        _validate_id(presentation_id, "presentation_id")
        key = (credential_id, presentation_id)
        with self._lock:
            if key in self._entries:
                return False
            self._entries[key] = {
                "credential_id": credential_id,
                "presentation_id": presentation_id,
                "seen_at": _normalize_time(seen_at, "seen_at"),
            }
            return True

    def is_seen(self, credential_id, presentation_id):
        """Return True iff this pair was already recorded.

        Non-string ids are never seen; this is a lookup, not a
        validation point, matching ``RevocationList.is_revoked``.
        """
        if not isinstance(credential_id, str) or not isinstance(
            presentation_id, str
        ):
            return False
        with self._lock:
            return (credential_id, presentation_id) in self._entries

    def __len__(self):
        with self._lock:
            return len(self._entries)

    def entries(self):
        """Return copies of all entries, in first-seen order."""
        with self._lock:
            return [dict(entry) for entry in self._entries.values()]

    def prune(self, *, seen_before):
        """Drop entries first seen before a cutoff. Returns the count dropped.

        This is the store's only way to shrink, and it is deliberately
        the caller's decision: an entry may only be dropped safely once
        the credential it guards can no longer be presented (its
        session window has passed). Pruning an entry for a credential
        that is still inside its window reopens the replay hole for
        that credential, so the cutoff should be no later than the
        oldest still-valid credential window the caller cares about.
        """
        cutoff = _normalize_time(seen_before, "seen_before")
        with self._lock:
            doomed = [
                key
                for key, entry in self._entries.items()
                if entry["seen_at"] < cutoff
            ]
            for key in doomed:
                del self._entries[key]
            return len(doomed)

    def to_dict(self):
        """Serialize to a plain JSON-serializable dict."""
        return {
            "version": REPLAY_STORE_VERSION,
            "entries": self.entries(),
        }

    @classmethod
    def from_dict(cls, data):
        """Load a store from ``to_dict`` output. Raises ValueError if malformed."""
        if not isinstance(data, dict):
            raise ValueError("replay store data must be a dict")
        if type(data.get("version")) is not int or data["version"] != REPLAY_STORE_VERSION:
            raise ValueError(
                "unsupported replay store version: %r" % (data.get("version"),)
            )
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise ValueError("replay store entries must be a list")
        return cls(entries)

    def to_json(self):
        """Serialize to a JSON string (sorted keys, no extra whitespace)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, text):
        """Load a store from ``to_json`` output. Raises ValueError if malformed."""
        if not isinstance(text, str):
            raise ValueError("replay store JSON must be a string")
        try:
            data = json.loads(text, object_pairs_hook=_unique_json_object)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid replay store JSON") from exc
        return cls.from_dict(data)


def consume_presentation(replay_store, credential_id, presentation_id, *, seen_at=None):
    """Spend one presentation against a store, for the authorizers.

    Returns (True, "ok") when the presentation is new and has been
    recorded, (False, "missing_presentation_id") when a store was
    supplied but the presentation carries no usable id, and
    (False, "replay") when the pair was already spent. A store that is
    not a ``ReplayStore`` (duck-typed: anything with a callable
    ``check_and_record``) raises ``TypeError``, because silently
    skipping replay checks on a mistyped store would fail open.
    """
    if not callable(getattr(replay_store, "check_and_record", None)):
        raise TypeError(
            "replay_store must be a ReplayStore (an object with "
            "check_and_record)"
        )
    if not isinstance(credential_id, str) or not credential_id:
        return False, REASON_MALFORMED
    if not isinstance(presentation_id, str) or not presentation_id:
        return False, REASON_MISSING_PRESENTATION_ID
    if replay_store.check_and_record(
        credential_id, presentation_id, seen_at=seen_at
    ):
        return True, "ok"
    return False, REASON_REPLAY
