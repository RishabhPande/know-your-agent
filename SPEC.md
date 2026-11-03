# Know Your Agent (KYA) - starter spec, v0.1

## Problem (README lead)
AI agents now shop, book, and pay on behalf of humans, but fraud systems still see
only a human account behind the transaction. When an agent acts, nobody can answer
three questions cryptographically: which agent is this, who authorized it, and what
exactly is it allowed to do? This toolkit gives every agent transaction a verifiable
identity: scoped, session-limited, and revocable.

## What v0.1 ships
1. Agent credential model: an agent credential binds an agent ID to a human principal,
   a scope (what it may do, e.g. "purchase up to $X in category Y"), a session window,
   and a revocation handle. Credentials are signed (Ed25519) and JSON-serializable.
2. Issue and verify: `issue_credential()` and `verify_credential()` with expiry,
   scope, and signature checks. Verification fails closed on any tampering or expiry.
3. Delegation chains: an agent may delegate a subset of its scope to a sub-agent.
   Verification walks the chain and enforces that scope only narrows, never widens.
4. Demo: a runnable end-to-end script. A shopping agent gets a credential, makes a
   purchase within scope (accepted), tries one outside scope (rejected), then gets
   revoked and retries (rejected). No servers, no accounts, runs in minutes.
5. Revocation management: a RevocationList owns the revoked ids, with a
   revoke API, verification-time lookup, and JSON persistence. Revocation is
   permanent: a revoked credential fails verification even inside its
   session window, and revoking any link in a delegation chain fails the
   whole chain.
6. Audit trail: an AuditLog records issuance, verification, and revocation
   as signed, hash-chained entries, with JSON persistence and fail-closed
   verification (malformed, bad_index, bad_hash_chain, bad_signature).
   Tampering with a middle entry breaks the chain; tail truncation is
   caught only by an external anchor passed as expected_last_hash.

## Planned next (not yet shipped)
- Benchmark hook: score a fraud model on agent traffic using KYA verdicts
  as labels, linking back to the AgentRisk work.

## Shipped since v0.1
- FastAPI demo service (DONE 2026-11-03: service/app.py, create_app
  with /health, /verify, /verify-chain, /checkout, /revoke, /audit;
  fail-closed HTTP answers matching the library reasons; revocation
  and audit wired in; service/demo.py runnable demo printing a sample
  credential; 18 new tests, 88 total green).

## Design rules
- No real money, no real credentials, no vendor lock-in. Pure Python, minimal deps
  (cryptography only for v0.1). Every check is offline and deterministic.
- Fail closed: anything unverifiable is rejected, with a reason code.
- Spec-first: the credential format is documented in SPEC.md before code, so other
  implementations can interoperate.

## 48-hour improvement backlog (in order)
1. v0.1 core: credential model + issue/verify + demo + README (this spec).
2. Delegation chains (DONE 2026-10-28: kya/delegation.py, delegate_credential,
   verify_chain, authorize_purchase_chain; scope only narrows, window only
   shrinks, principal fixed; 16 new tests, 29 total green).
3. Revocation management (DONE 2026-10-30: kya/revocation.py, RevocationList
   with revoke/revoke_credential, permanent entries, JSON round-trip, and
   verification-time lookup in verify_credential, verify_chain, and the
   purchase authorizers; revoking a chain link fails the whole chain;
   14 new tests, 43 total green).
4. Audit trail (DONE 2026-11-01: kya/audit.py, AuditLog with
   record_issued / record_verified / record_revoked, hash-chained
   entries, Ed25519 signatures, JSON round-trip, and fail-closed
   verification with an external-anchor check for tail truncation;
   15 new tests, 70 total green).
5. FastAPI demo service (DONE 2026-11-03: service/app.py, create_app
   with /health, /verify, /verify-chain, /checkout, /revoke, /audit;
   fail-closed HTTP answers matching the library reasons; revocation
   and audit wired in; service/demo.py runnable demo; 18 new tests,
   88 total green).
6. Benchmark hook: score a fraud model on agent traffic using KYA verdicts as labels,
   linking back to the AgentRisk work (NEXT).

## Naming and license (suggested)
- Repo: `know-your-agent` (public)
- License: MIT (widest adoption for a toolkit)
- Language: Python (matches his stack; cryptography lib for Ed25519)
