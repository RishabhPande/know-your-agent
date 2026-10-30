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

## Planned next (not yet shipped)
- Revocation management: a maintained revocation list with a revoke API
  and verification-time lookup, so a revoked credential fails verification
  even inside its session window.
- Audit trail: every issuance, verification, and revocation appends a signed,
  append-only log entry, so a disputed transaction can be reconstructed.

## Design rules
- No real money, no real credentials, no vendor lock-in. Pure Python, minimal deps
  (cryptography only for v0.1). Every check is offline and deterministic.
- Fail closed: anything unverifiable is rejected, with a reason code.
- Spec-first: the credential format is documented in SPEC.md before code, so other
  implementations can interoperate.

## 48-hour improvement backlog (in order)
1. v0.1 core: credential model + issue/verify + demo + README (this spec).
2. Delegation chains (DONE 2026-10-28: kya/delegation.py — delegate_credential,
   verify_chain, authorize_purchase_chain; scope only narrows, window only
   shrinks, principal fixed; 16 new tests, 29 total green).
3. Revocation management: a maintained revocation list with a revoke API
   and verification-time lookup (NEXT).
4. Audit trail: a signed, append-only log of issuance, verification, and
   revocation, so a disputed transaction can be reconstructed.
5. FastAPI demo service: verify endpoint + a tiny merchant checkout example.
6. Benchmark hook: score a fraud model on agent traffic using KYA verdicts as labels,
   linking back to the AgentRisk work.

## Naming and license (suggested)
- Repo: `know-your-agent` (public)
- License: MIT (widest adoption for a toolkit)
- Language: Python (matches his stack; cryptography lib for Ed25519)
