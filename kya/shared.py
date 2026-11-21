"""Shared, persistent state for multi-process Know Your Agent deployments.

The revocation and replay stores shipped earlier keep their state in
one process's memory, with ``to_json`` / ``from_json`` as the only way
to move it. That leaves the honest limit named in ``kya/replay.py``:
two merchant processes that do not share a store do not share state,
so a credential revoked in one process still verifies in another, and
a presentation spent in one process can be replayed in another.

This module closes that limit with file-backed versions of both
stores. ``FileRevocationList`` and ``FileReplayStore`` keep the exact
public behaviour of ``RevocationList`` and ``ReplayStore`` (same
methods, same return values, same fail-closed validation), but every
read reloads the state from a JSON file on disk and every mutation
rewrites that file, so any number of processes pointing at the same
path agree on the state, and the state survives a restart.

How agreement is kept:

1. Mutual exclusion. Each operation takes an exclusive advisory lock
   (``fcntl.flock``) on a sibling ``<path>.lock`` file for the whole
   reload, change, write cycle, so two processes cannot interleave a
   read and a write and lose each other's update. On platforms
   without ``fcntl`` the lock degrades to a no-op and the atomic
   write below still prevents torn files, but concurrent writers are
   no longer fully serialized; that platform limit is stated here
   rather than hidden.
2. Atomic writes. New state is written to a temporary file in the
   same directory and moved over the old file with ``os.replace``,
   so a reader never sees a half-written file and a crash mid-write
   leaves the previous state intact.
3. Fail closed on a damaged file. A state file that exists but does
   not parse, or parses to malformed entries, raises ``ValueError``
   instead of starting empty. Starting empty would silently
   un-revoke credentials and forget spent presentations, which is
   exactly the failure these stores exist to prevent. A missing
   file is different: it simply means no state has been recorded
   yet, so the store starts empty and the file is created on the
   first mutation.

The on-disk format is exactly the ``to_json`` format of the
in-memory stores, so a file written by hand, by ``to_json``, or by
an older version loads here unchanged, and state can be moved
between an in-memory store and a file-backed one freely.
"""

import contextlib
import json
import os
import tempfile

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

from .replay import REPLAY_STORE_VERSION, ReplayStore
from .revocation import REVOCATION_LIST_VERSION, RevocationList


@contextlib.contextmanager
def _locked(path):
    """Hold an exclusive advisory lock for one state file.

    The lock lives on a sibling ``<path>.lock`` file that is created
    if needed and never deleted, because deleting a lock file another
    process holds would break the exclusion it provides.
    """
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT|os.O_RDWR, 0o644)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_state_text(path):
    """Return the state file text, or None when the file is absent."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return None
    except IsADirectoryError as exc:
        raise ValueError("state path is a directory: %r" % path) from exc


def _write_state_text(path, text):
    """Atomically replace the state file with new text."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".kya-state-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _validate_path(path):
    if not isinstance(path, (str, os.PathLike)) or not str(path):
        raise ValueError("state path must be a non-empty path")
    return os.fspath(path)


class FileRevocationList(RevocationList):
    """A ``RevocationList`` backed by a shared JSON file.

    Every method reloads from the file first, and ``revoke`` and
    ``revoke_credential`` write the merged state back before
    returning, all under the file lock. Two instances, in this
    process or in different processes, that share a path therefore
    see each other's revocations immediately.
    """

    def __init__(self, path):
        self._path = _validate_path(path)
        super().__init__()
        with _locked(self._path):
            self._reload_locked()

    # -- file plumbing -------------------------------------------------

    def _reload_locked(self):
        """Reload entries from disk. Caller must hold the lock."""
        text = _read_state_text(self._path)
        if text is None:
            self._entries = {}
            return
        loaded = RevocationList.from_json(text)
        self._entries = dict(loaded._entries)

    def _refresh(self):
        with _locked(self._path):
            self._reload_locked()

    def _persist_locked(self):
        # Raw serialization only: the public to_json reloads, and
        # reloading would try to take the lock this call already holds.
        text = json.dumps(
            {
                "version": REVOCATION_LIST_VERSION,
                "entries": [dict(e) for e in self._entries.values()],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        _write_state_text(self._path, text)

    @property
    def path(self):
        return self._path

    # -- mutations -------------------------------------------------------

    def revoke(self, credential_id, *, reason=None, revoked_at=None):
        with _locked(self._path):
            self._reload_locked()
            newly = super().revoke(
                credential_id, reason=reason, revoked_at=revoked_at
            )
            if newly:
                self._persist_locked()
            return newly

    def revoke_credential(self, credential, *, reason=None, revoked_at=None):
        # Extract the id first so a malformed credential raises before
        # any file work, matching the in-memory behaviour.
        if not isinstance(credential, dict):
            raise ValueError("credential must be a credential dict")
        payload = credential.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("credential has no payload")
        credential_id = payload.get("credential_id")
        return self.revoke(credential_id, reason=reason, revoked_at=revoked_at)

    # -- reads (each reloads, so peers' writes are visible) --------------

    def is_revoked(self, credential_id):
        self._refresh()
        return super().is_revoked(credential_id)

    def __contains__(self, credential_id):
        return self.is_revoked(credential_id)

    def __len__(self):
        self._refresh()
        return super().__len__()

    def revoked_ids(self):
        self._refresh()
        return super().revoked_ids()

    def get(self, credential_id):
        self._refresh()
        return super().get(credential_id)

    def entries(self):
        self._refresh()
        return super().entries()

    def to_dict(self):
        self._refresh()
        return super().to_dict()

    def to_json(self):
        self._refresh()
        return super().to_json()


class FileReplayStore(ReplayStore):
    """A ``ReplayStore`` backed by a shared JSON file.

    ``check_and_record`` runs its whole reload, check, record, write
    cycle under the file lock, so two processes presenting the same
    (credential_id, presentation_id) pair at the same time cannot
    both be told the presentation is new: exactly one wins and the
    other sees the recorded pair and is rejected as a replay.
    """

    def __init__(self, path):
        self._path = _validate_path(path)
        super().__init__()
        with _locked(self._path):
            self._reload_locked()

    # -- file plumbing -------------------------------------------------

    def _reload_locked(self):
        text = _read_state_text(self._path)
        if text is None:
            self._entries = {}
            return
        loaded = ReplayStore.from_json(text)
        self._entries = dict(loaded._entries)

    def _refresh(self):
        with _locked(self._path):
            self._reload_locked()

    def _persist_locked(self):
        # Raw serialization only: the public to_json reloads, and
        # reloading would try to take the lock this call already holds.
        text = json.dumps(
            {
                "version": REPLAY_STORE_VERSION,
                "entries": [dict(e) for e in self._entries.values()],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        _write_state_text(self._path, text)

    @property
    def path(self):
        return self._path

    # -- mutations -------------------------------------------------------

    def check_and_record(self, credential_id, presentation_id, *, seen_at=None):
        with _locked(self._path):
            self._reload_locked()
            is_new = super().check_and_record(
                credential_id, presentation_id, seen_at=seen_at
            )
            if is_new:
                self._persist_locked()
            return is_new

    def prune(self, *, seen_before):
        with _locked(self._path):
            self._reload_locked()
            dropped = super().prune(seen_before=seen_before)
            if dropped:
                self._persist_locked()
            return dropped

    # -- reads -----------------------------------------------------------

    def is_seen(self, credential_id, presentation_id):
        self._refresh()
        return super().is_seen(credential_id, presentation_id)

    def __len__(self):
        self._refresh()
        return super().__len__()

    def entries(self):
        self._refresh()
        return super().entries()

    def to_dict(self):
        self._refresh()
        return super().to_dict()

    def to_json(self):
        self._refresh()
        return super().to_json()
