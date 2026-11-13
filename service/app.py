"""FastAPI demo service for Know Your Agent.

This is the merchant side of the toolkit: a small HTTP service that
verifies agent credentials and authorizes purchases against them, using
exactly the same fail-closed checks as the library. It holds no private
keys and issues no credentials. It trusts one issuer public key, given
to ``create_app()`` at startup, plus a ``RevocationList`` and, optionally,
an ``AuditLog``.

Endpoints:

- ``GET /health``: liveness, no credential needed.
- ``POST /verify``: verify one credential, returns ``ok`` and ``reason``.
- ``POST /verify-chain``: verify a delegation chain, same shape.
- ``POST /checkout``: verify a credential and check one purchase against
  its scope, returns ``accepted`` and ``reason``.
- ``POST /checkout-chain``: verify every delegation link, then check the leaf purchase scope.
- ``POST /revoke``: revoke a credential id (or a full credential, which
  also records the revocation in the audit log when one is configured).
- ``GET /audit``: the audit log entries plus their verification result,
  when an audit log is configured; 404 otherwise.
- ``POST /benchmark``: score a fraud model against KYA-labeled records
  (``{"records": [...], "threshold": 0.5}``), returning the confusion
  matrix, precision, recall, F1, accuracy, and AUC. A malformed record
  is a 422, never a score.
- ``POST /benchmark/agentrisk``: score one AgentRisk policy with the
  benchmark hook, either on caller-supplied rows or, when ``rows`` is
  omitted, on the bundled AgentRisk snapshot. With ``per_seed`` set,
  each seed is scored separately and every metric comes back with a
  confidence interval, computed from the bundled per-seed snapshot
  when ``rows`` is omitted. A malformed row, an unknown policy, or
  an unsupported option is a 422, never a score.

Failure handling is fail-closed all the way down. A malformed credential
is a ``{"ok": false, "reason": "malformed"}`` response, never a 500 and
never an acceptance. A request that is not even valid JSON for the
endpoint shape (a list where a credential object belongs, a missing
field) is rejected by request validation with a 422, which is also a
rejection, not an acceptance. Nothing in this service ever accepts a
purchase on a best effort basis.

Run the runnable demo (fresh in-memory keys, a sample credential printed
to stdout) with::

    python -m service.demo

That demo is for trying the endpoints locally. Demo keys are generated
in memory and discarded on exit; never point this service at a real
issuer key and then reuse the demo credential for real authorization.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from kya import (
    RevocationList,
    authorize_purchase,
    authorize_purchase_chain,
    bundled_per_seed_results_path,
    bundled_results_path,
    load_agentrisk_csv,
    score_agentrisk_policy,
    score_agentrisk_policy_per_seed,
    score_model,
    verify_chain,
    verify_credential,
)


class VerifyRequest(BaseModel):
    credential: dict


class VerifyChainRequest(BaseModel):
    chain: list


class CheckoutRequest(BaseModel):
    credential: dict
    amount_usd: float
    category: str


class CheckoutChainRequest(BaseModel):
    chain: list
    amount_usd: float
    category: str


class RevokeRequest(BaseModel):
    credential: dict | None = None
    credential_id: str | None = None
    reason: str | None = None


class BenchmarkRequest(BaseModel):
    records: list
    threshold: float = 0.5


class BenchmarkAgentRiskRequest(BaseModel):
    policy: str
    rows: list | None = None
    threshold: float = 0.5
    seed: int | str | None = None
    score_column: str | None = None
    per_seed: bool = False
    confidence: float = 0.95


def _payload_of(credential):
    """Return the payload dict of a credential, or None when unusable."""
    if not isinstance(credential, dict):
        return None
    payload = credential.get("payload")
    return payload if isinstance(payload, dict) else None


def _auditable_payload(credential):
    """Return a payload usable for an audit entry, or None.

    An audit entry needs a credential id, an agent id, and a principal,
    all non-empty strings. A credential too malformed to supply those
    still gets its verify verdict from the endpoint, it just leaves no
    audit entry, because an entry with invented fields would be worse
    than no entry.
    """
    payload = _payload_of(credential)
    if payload is None:
        return None
    for field in ("credential_id", "agent_id", "principal"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            return None
    return payload


def _record_verified(app, credential, ok, reason):
    """Record a verification in the app audit log when possible."""
    audit = getattr(app.state, "audit", None)
    if audit is None:
        return
    if _auditable_payload(credential) is None:
        return
    try:
        audit.record_verified(credential, ok, reason)
    except ValueError:
        # Audit recording must never change a verdict. The verify
        # result already went out; a log that cannot record the entry
        # is a logging problem, not a reason to flip an answer.
        pass


def create_app(public_key, *, revocations=None, audit=None, audit_public_key=None):
    """Build the demo service app for one trusted issuer public key.

    Args:
        public_key: Ed25519 public key of the issuer whose credentials
            this service accepts.
        revocations: a ``RevocationList`` to check and to add to. A
            fresh empty list is created when omitted, so each app owns
            its revocation state unless the caller shares one.
        audit: an optional ``AuditLog``. When given, verifications,
            checkouts, and full-credential revocations are recorded in
            it, and ``GET /audit`` serves it. When omitted, the audit
            endpoint reports that no log is configured.
        audit_public_key: public key that signed the audit log, when
            it differs from the issuer key. Defaults to ``public_key``,
            which is the demo setup, where one key signs both.

    Returns a FastAPI app. The app holds no private key material.
    """
    app = FastAPI(title="Know Your Agent demo service")
    app.state.public_key = public_key
    app.state.revocations = (
        revocations if revocations is not None else RevocationList()
    )
    app.state.audit = audit
    app.state.audit_public_key = (
        audit_public_key if audit_public_key is not None else public_key
    )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/verify")
    def verify(request: VerifyRequest):
        ok, reason = verify_credential(
            app.state.public_key,
            request.credential,
            revoked_ids=app.state.revocations,
        )
        _record_verified(app, request.credential, ok, reason)
        return {"ok": ok, "reason": reason}

    @app.post("/verify-chain")
    def verify_chain_endpoint(request: VerifyChainRequest):
        ok, reason = verify_chain(
            app.state.public_key,
            request.chain,
            revoked_ids=app.state.revocations,
        )
        if isinstance(request.chain, list) and request.chain:
            _record_verified(app, request.chain[-1], ok, reason)
        return {"ok": ok, "reason": reason}

    @app.post("/checkout")
    def checkout(request: CheckoutRequest):
        accepted, reason = authorize_purchase(
            app.state.public_key,
            request.credential,
            request.amount_usd,
            request.category,
            revoked_ids=app.state.revocations,
        )
        # Record the checkout verdict itself ("allowed" or the failure
        # reason), not just the verification verdict, so the log reads
        # the way the merchant decision read.
        audit = getattr(app.state, "audit", None)
        payload = _auditable_payload(request.credential)
        if audit is not None and payload is not None:
            try:
                audit.append(
                    "verified",
                    payload["credential_id"],
                    agent_id=payload["agent_id"],
                    principal=payload["principal"],
                    outcome=reason,
                    detail={"endpoint": "checkout"},
                )
            except ValueError:
                pass
        return {"accepted": accepted, "reason": reason}

    @app.post("/checkout-chain")
    def checkout_chain(request: CheckoutChainRequest):
        accepted, reason = authorize_purchase_chain(
            app.state.public_key,
            request.chain,
            request.amount_usd,
            request.category,
            revoked_ids=app.state.revocations,
        )
        # Record only a usable leaf identity; malformed chains still reject
        # without inventing an audit identity or changing their verdict.
        audit = getattr(app.state, "audit", None)
        leaf = request.chain[-1] if request.chain else None
        payload = _auditable_payload(leaf)
        if audit is not None and payload is not None:
            try:
                audit.append(
                    "verified", payload["credential_id"],
                    agent_id=payload["agent_id"], principal=payload["principal"],
                    outcome=reason, detail={"endpoint": "checkout-chain"},
                )
            except ValueError:
                pass
        return {"accepted": accepted, "reason": reason}

    @app.post("/revoke")
    def revoke(request: RevokeRequest):
        if request.credential is not None:
            payload = _payload_of(request.credential)
            if payload is None or not isinstance(
                payload.get("credential_id"), str
            ):
                raise HTTPException(
                    status_code=422, detail="credential has no credential_id"
                )
            credential_id = payload["credential_id"]
            try:
                newly_revoked = app.state.revocations.revoke_credential(
                    request.credential, reason=request.reason
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            audit = getattr(app.state, "audit", None)
            if audit is not None and _auditable_payload(request.credential):
                try:
                    audit.record_revoked(
                        request.credential, reason=request.reason
                    )
                except ValueError:
                    pass
            return {"revoked": newly_revoked, "credential_id": credential_id}
        if request.credential_id is not None:
            try:
                newly_revoked = app.state.revocations.revoke(
                    request.credential_id, reason=request.reason
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            return {"revoked": newly_revoked, "credential_id": request.credential_id}
        raise HTTPException(
            status_code=422,
            detail="revoke needs a credential or a credential_id",
        )

    @app.get("/audit")
    def audit_entries():
        audit = getattr(app.state, "audit", None)
        if audit is None:
            raise HTTPException(
                status_code=404, detail="audit log not configured"
            )
        ok, reason = audit.verify(app.state.audit_public_key)
        return {"ok": ok, "reason": reason, "entries": audit.entries()}

    @app.post("/benchmark")
    def benchmark(request: BenchmarkRequest):
        try:
            return score_model(request.records, threshold=request.threshold)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/benchmark/agentrisk")
    def benchmark_agentrisk(request: BenchmarkAgentRiskRequest):
        # Rows are optional on purpose: the package ships snapshots of
        # the AgentRisk results, so a caller can score a policy by name
        # alone. An explicit empty list is not the same as omitting
        # rows; it scores nothing and the library rejects it as a 422.
        try:
            if request.per_seed:
                if request.seed is not None:
                    raise ValueError(
                        "seed cannot be combined with per_seed scoring"
                    )
                rows = (
                    request.rows
                    if request.rows is not None
                    else load_agentrisk_csv(bundled_per_seed_results_path())
                )
                per_seed, summary = score_agentrisk_policy_per_seed(
                    rows,
                    request.policy,
                    threshold=request.threshold,
                    confidence=request.confidence,
                    score_column=request.score_column,
                )
                return {"per_seed": per_seed, "summary": summary}
            rows = (
                request.rows
                if request.rows is not None
                else load_agentrisk_csv(bundled_results_path())
            )
            _records, counts, result = score_agentrisk_policy(
                rows,
                request.policy,
                threshold=request.threshold,
                seed=request.seed,
                score_column=request.score_column,
            )
            return {"counts": counts, "result": result}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return app
