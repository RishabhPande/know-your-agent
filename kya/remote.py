"""Cross-machine shared state for Know Your Agent deployments.

``kya/shared.py`` made revocation and replay state agree across
processes on one machine, through a shared JSON file. Its stated
limit is the filesystem: processes on different machines do not see
the same file, so a credential revoked on one machine still verifies
on another, and a presentation spent on one machine can be replayed
on another.

This module closes that limit with a shared backend reached over
HTTP. One machine runs the state service (the demo service in
``service/app.py`` serves the endpoints below from the same
revocation list and replay store it authorizes against), and every
other machine uses ``RemoteRevocationList`` and ``RemoteReplayStore``
as drop-in replacements for the local stores. They keep the exact
public behaviour of ``RevocationList`` and ``ReplayStore`` - same
methods, same return values, same validation of the caller's own
arguments before any request is made - but every read asks the
backend and every mutation is performed by the backend, so all
machines agree on one state, held in one place.

The wire contract is small and is the same JSON the local stores
already speak:

- ``GET /state/revocations`` returns the revocation list in
  ``RevocationList.to_dict`` form.
- ``GET /state/revocations/<credential_id>`` returns
  ``{"revoked": bool, "entry": entry-or-null}``.
- ``POST /state/revocations`` with ``{"credential_id": ...,
  "reason": ..., "revoked_at": ...}`` revokes and returns
  ``{"revoked": newly, "entry": entry}``.
- ``GET /state/replay`` returns the replay store in
  ``ReplayStore.to_dict`` form.
- ``POST /state/replay/check-and-record`` with
  ``{"credential_id": ..., "presentation_id": ..., "seen_at": ...}``
  records a presentation atomically on the backend and returns
  ``{"is_new": bool}``. Atomicity matters here: two machines racing
  the same presentation must not both be told it is new, and only
  the backend can serialize that race.
- ``POST /state/replay/lookup`` returns ``{"seen": bool}``.
- ``POST /state/replay/prune`` with ``{"seen_before": ...}`` returns
  ``{"pruned": count}``.

Fail-closed rules:

1. No local fallback. A remote store holds no authoritative copy of
   its own. If the backend is unreachable, answers with an error
   status, or answers with malformed data, the call raises
   ``RemoteStateError`` (or ``ValueError`` for a backend validation
   rejection, matching the local stores). It never guesses from a
   stale cache, because a guessed "not revoked" or "not seen" is
   exactly the failure these stores exist to prevent.
2. Responses are validated strictly. A revocation or replay payload
   is parsed through the local stores' own ``from_dict`` validation,
   and single-value answers must carry the exact boolean or count
   they promise. Anything else is a ``RemoteStateError``.
3. Caller arguments are validated locally first, the same way the
   local stores validate them, so a bad id or time raises
   ``ValueError`` without a round trip.

Transport is pluggable so the contract can be tested without a
network: a transport is a callable ``(method, path, payload)`` that
returns ``(status, parsed_json)``, where ``payload`` is a dict or
None. When a store carries an ``auth_token``, the transport is
called with a fourth argument, ``headers``, a dict holding the
``Authorization`` header to send; a transport that cannot accept
that argument cannot carry authentication, and the store fails
closed with ``RemoteStateError`` instead of silently sending the
request unauthenticated. The default transport speaks HTTP with
``urllib`` to a ``base_url`` and sends the header itself.
``InProcessTransport`` runs the same contract against local stores
in this process; it is what the demo and the library tests use to
stand in for the backend, and it is also a reasonable way to give
several in-process consumers one shared state object with
remote-store semantics.

Authentication is one optional shared bearer token. Pass
``auth_token`` to a remote store and ``state_token`` to the demo
service's ``create_app()`` (or ``auth_token`` to an
``InProcessTransport``) and every state request must carry
``Authorization: Bearer <token>``; a missing or wrong token is a
401 from the backend and a ``RemoteStateError`` on the client,
never a fallback to an unauthenticated retry. The comparison on
the service side uses ``secrets.compare_digest``. With no token
configured anywhere, behaviour is exactly what it was before:
open, for trusted networks only.

Two honest limits, stated plainly. First, one shared token is one
shared identity: it proves a caller knows the secret, not which
machine it is, and it does not encrypt anything, so the token
belongs on a TLS-protected or trusted network, the same advice as
before, now with a lock on the door as well. Second, this covers
only the state contract: the demo service's other endpoints,
including ``/revoke``, stay unauthenticated, because they are a
local demo surface, not a deployment API.
"""

import inspect
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

from .replay import ReplayStore, _validate_id
from .revocation import RevocationList, _validate_credential_id

REMOTE_STATE_VERSION = 1


class RemoteStateError(RuntimeError):
    """The shared backend could not be reached or answered badly.

    Raised instead of falling back to any local state: a caller that
    cannot learn the shared revocation or replay state must fail,
    not guess.
    """


def _validate_auth_token(auth_token):
    if auth_token is None:
        return None
    if not isinstance(auth_token, str) or not auth_token:
        raise ValueError("auth_token must be a non-empty string or None")
    return auth_token


def _auth_headers(auth_token):
    if auth_token is None:
        return None
    return {"Authorization": "Bearer " + auth_token}


def _transport_accepts_headers(transport):
    """True when a transport can be called with a headers argument."""
    try:
        parameters = inspect.signature(transport).parameters.values()
    except (TypeError, ValueError):
        return False
    positional = 0
    for parameter in parameters:
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            return True
        if parameter.name == "headers":
            return True
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional += 1
    return positional >= 4


def _urllib_transport(base_url, timeout, auth_token=None):
    base = base_url.rstrip("/")

    def transport(method, path, payload, headers=None):
        data = None
        headers = {"Accept": "application/json"}
        if auth_token is not None:
            headers["Authorization"] = "Bearer " + auth_token
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                text = response.read().decode("utf-8")
                return response.status, (json.loads(text) if text else None)
        except urllib.error.HTTPError as exc:
            # An HTTP error status still carries a JSON answer the
            # caller should see (a 422 validation detail, say).
            try:
                parsed = json.loads(exc.read().decode("utf-8"))
            except Exception:
                parsed = None
            return exc.code, parsed
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RemoteStateError(
                "shared state backend unreachable: %s" % exc
            ) from exc

    return transport


class InProcessTransport:
    """The state contract served from local stores, without a network.

    Holds one ``RevocationList`` and one ``ReplayStore`` and answers
    transport calls against them, exactly the way the HTTP endpoints
    in ``service/app.py`` answer against the service's stores. Two
    remote stores built on two transports that share one backend
    object therefore agree, which is the property the demo and the
    tests exercise.
    """

    def __init__(self, revocations=None, replay_store=None, *, auth_token=None):
        self.revocations = (
            revocations if revocations is not None else RevocationList()
        )
        self.replay_store = (
            replay_store if replay_store is not None else ReplayStore()
        )
        self._auth_token = _validate_auth_token(auth_token)

    def __call__(self, method, path, payload, headers=None):
        if self._auth_token is not None:
            expected = "Bearer " + self._auth_token
            presented = headers.get("Authorization") if isinstance(
                headers, dict
            ) else None
            if not isinstance(presented, str) or not secrets.compare_digest(
                presented, expected
            ):
                return 401, {"detail": "state backend requires authentication"}
        payload = payload or {}
        try:
            if method == "GET" and path == "/state/revocations":
                return 200, self.revocations.to_dict()
            if method == "GET" and path.startswith("/state/revocations/"):
                credential_id = urllib.parse.unquote(
                    path[len("/state/revocations/"):]
                )
                entry = self.revocations.get(credential_id)
                return 200, {"revoked": entry is not None, "entry": entry}
            if method == "POST" and path == "/state/revocations":
                newly = self.revocations.revoke(
                    payload.get("credential_id"),
                    reason=payload.get("reason"),
                    revoked_at=payload.get("revoked_at"),
                )
                return 200, {
                    "revoked": newly,
                    "entry": self.revocations.get(payload.get("credential_id")),
                }
            if method == "GET" and path == "/state/replay":
                return 200, self.replay_store.to_dict()
            if method == "POST" and path == "/state/replay/check-and-record":
                is_new = self.replay_store.check_and_record(
                    payload.get("credential_id"),
                    payload.get("presentation_id"),
                    seen_at=payload.get("seen_at"),
                )
                return 200, {"is_new": is_new}
            if method == "POST" and path == "/state/replay/lookup":
                seen = self.replay_store.is_seen(
                    payload.get("credential_id"),
                    payload.get("presentation_id"),
                )
                return 200, {"seen": seen}
            if method == "POST" and path == "/state/replay/prune":
                pruned = self.replay_store.prune(
                    seen_before=payload.get("seen_before")
                )
                return 200, {"pruned": pruned}
        except ValueError as exc:
            return 422, {"detail": str(exc)}
        return 404, {"detail": "unknown state path: %s" % path}


def _resolve_transport(base_url, transport, timeout, auth_token=None):
    if transport is not None and base_url is not None:
        raise ValueError("pass either base_url or transport, not both")
    if transport is not None:
        if not callable(transport):
            raise ValueError("transport must be callable")
        return transport
    if not isinstance(base_url, str) or not base_url:
        raise ValueError("a non-empty base_url or a transport is required")
    return _urllib_transport(base_url, timeout, auth_token)


class _RemoteBase:
    def _request(self, method, path, payload=None):
        headers = _auth_headers(getattr(self, "_auth_token", None))
        try:
            if headers is None:
                status, parsed = self._transport(method, path, payload)
            elif _transport_accepts_headers(self._transport):
                status, parsed = self._transport(
                    method, path, payload, headers
                )
            else:
                raise RemoteStateError(
                    "transport cannot carry authentication headers; "
                    "refusing to call the shared state backend "
                    "unauthenticated"
                )
        except RemoteStateError:
            raise
        except Exception as exc:
            raise RemoteStateError(
                "shared state backend call failed: %s" % exc
            ) from exc
        if status in (401, 403):
            raise RemoteStateError(
                "shared state backend rejected authentication "
                "(status %r) for %s %s" % (status, method, path)
            )
        if status == 422:
            detail = parsed.get("detail") if isinstance(parsed, dict) else None
            raise ValueError(detail or "shared state backend rejected the request")
        if status != 200:
            raise RemoteStateError(
                "shared state backend answered status %r for %s %s"
                % (status, method, path)
            )
        if not isinstance(parsed, dict):
            raise RemoteStateError(
                "shared state backend answered a non-object payload for %s %s"
                % (method, path)
            )
        return parsed


class RemoteRevocationList(_RemoteBase, RevocationList):
    """A ``RevocationList`` whose state lives on a shared backend.

    Every method asks the backend; nothing is cached between calls,
    so a revocation made on another machine is visible on the very
    next check here.
    """

    def __init__(
        self, base_url=None, *, transport=None, timeout=5.0, auth_token=None
    ):
        self._auth_token = _validate_auth_token(auth_token)
        self._transport = _resolve_transport(
            base_url, transport, timeout, self._auth_token
        )
        super().__init__()
        # Fail fast at construction when the backend cannot serve
        # the contract, rather than at the first real check.
        self._fetch()

    def _fetch(self):
        data = self._request("GET", "/state/revocations")
        loaded = RevocationList.from_dict(data)
        self._entries = dict(loaded._entries)
        return loaded

    def revoke(self, credential_id, *, reason=None, revoked_at=None):
        _validate_credential_id(credential_id)
        if reason is not None and not isinstance(reason, str):
            raise ValueError("revocation reason must be a string or None")
        normalized_at = None
        if revoked_at is not None:
            # Validate (and normalize) locally, through the in-memory
            # store's own rules, before spending a round trip.
            probe = RevocationList()
            probe.revoke(credential_id, reason=reason, revoked_at=revoked_at)
            normalized_at = probe.get(credential_id)["revoked_at"]
        parsed = self._request(
            "POST",
            "/state/revocations",
            {
                "credential_id": credential_id,
                "reason": reason,
                "revoked_at": normalized_at,
            },
        )
        if not isinstance(parsed.get("revoked"), bool):
            raise RemoteStateError("backend revoke answer carries no boolean")
        entry = parsed.get("entry")
        if entry is not None:
            RevocationList(entries=[entry])
        return parsed["revoked"]

    def revoke_credential(self, credential, *, reason=None, revoked_at=None):
        if not isinstance(credential, dict):
            raise ValueError("credential must be a credential dict")
        payload = credential.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("credential has no payload")
        credential_id = payload.get("credential_id")
        _validate_credential_id(credential_id)
        return self.revoke(credential_id, reason=reason, revoked_at=revoked_at)

    def is_revoked(self, credential_id):
        if not isinstance(credential_id, str):
            return False
        parsed = self._request(
            "GET",
            "/state/revocations/" + urllib.parse.quote(credential_id, safe=""),
        )
        if not isinstance(parsed.get("revoked"), bool):
            raise RemoteStateError("backend lookup answer carries no boolean")
        return parsed["revoked"]

    def __contains__(self, credential_id):
        return self.is_revoked(credential_id)

    def __len__(self):
        return len(self._fetch())

    def revoked_ids(self):
        return self._fetch().revoked_ids()

    def get(self, credential_id):
        if not isinstance(credential_id, str):
            return None
        parsed = self._request(
            "GET",
            "/state/revocations/" + urllib.parse.quote(credential_id, safe=""),
        )
        entry = parsed.get("entry")
        if entry is None:
            return None
        return RevocationList(entries=[entry]).get(credential_id)

    def entries(self):
        return self._fetch().entries()

    def to_dict(self):
        return self._fetch().to_dict()

    def to_json(self):
        return self._fetch().to_json()


class RemoteReplayStore(_RemoteBase, ReplayStore):
    """A ``ReplayStore`` whose state lives on a shared backend.

    ``check_and_record`` is one backend call, so the check and the
    record are atomic where they are performed: on the backend, not
    split across a read here and a write there.
    """

    def __init__(
        self, base_url=None, *, transport=None, timeout=5.0, auth_token=None
    ):
        self._auth_token = _validate_auth_token(auth_token)
        self._transport = _resolve_transport(
            base_url, transport, timeout, self._auth_token
        )
        super().__init__()
        self._fetch()

    def _fetch(self):
        data = self._request("GET", "/state/replay")
        loaded = ReplayStore.from_dict(data)
        with self._lock:
            self._entries = dict(loaded._entries)
        return loaded

    def check_and_record(self, credential_id, presentation_id, *, seen_at=None):
        _validate_id(credential_id, "credential_id")
        _validate_id(presentation_id, "presentation_id")
        normalized_seen = None
        if seen_at is not None:
            probe = ReplayStore()
            probe.check_and_record(credential_id, presentation_id, seen_at=seen_at)
            normalized_seen = probe.entries()[0]["seen_at"]
        parsed = self._request(
            "POST",
            "/state/replay/check-and-record",
            {
                "credential_id": credential_id,
                "presentation_id": presentation_id,
                "seen_at": normalized_seen,
            },
        )
        if not isinstance(parsed.get("is_new"), bool):
            raise RemoteStateError("backend check-and-record answer carries no boolean")
        return parsed["is_new"]

    def is_seen(self, credential_id, presentation_id):
        if not isinstance(credential_id, str) or not isinstance(
            presentation_id, str
        ):
            return False
        parsed = self._request(
            "POST",
            "/state/replay/lookup",
            {"credential_id": credential_id, "presentation_id": presentation_id},
        )
        if not isinstance(parsed.get("seen"), bool):
            raise RemoteStateError("backend lookup answer carries no boolean")
        return parsed["seen"]

    def __len__(self):
        return len(self._fetch())

    def entries(self):
        return self._fetch().entries()

    def prune(self, *, seen_before):
        probe = ReplayStore()
        probe.check_and_record("probe", "probe", seen_at=seen_before)
        normalized = probe.entries()[0]["seen_at"]
        parsed = self._request(
            "POST", "/state/replay/prune", {"seen_before": normalized}
        )
        pruned = parsed.get("pruned")
        if not isinstance(pruned, int) or isinstance(pruned, bool) or pruned < 0:
            raise RemoteStateError("backend prune answer carries no count")
        return pruned

    def to_dict(self):
        return self._fetch().to_dict()

    def to_json(self):
        return self._fetch().to_json()
