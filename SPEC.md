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
- Backlog complete as of 2026-11-09 (see below). Candidate for the
  next loop, uncommitted: a POST /checkout-chain endpoint in the
  demo service, authorizing a purchase against the leaf of a
  delegation chain over HTTP.

## Shipped since v0.1
- AgentRisk benchmark endpoint (DONE 2026-11-11: POST
  /benchmark/agentrisk in service/app.py, scoring one policy on
  caller-supplied rows or on the bundled snapshot when rows are
  omitted, with a per_seed mode returning per-seed results and
  confidence-interval summaries from the bundled per-seed snapshot;
  seed and per_seed cannot be combined; every library ValueError is
  a 422, matching POST /benchmark; 16 new tests, 192 total green).
- FastAPI demo service (DONE 2026-11-03: service/app.py, create_app
  with /health, /verify, /verify-chain, /checkout, /revoke, /audit;
  fail-closed HTTP answers matching the library reasons; revocation
  and audit wired in; service/demo.py runnable demo printing a sample
  credential; 18 new tests, 88 total green).
- Benchmark hook (DONE 2026-11-05: kya/benchmark.py, score_model with
  confusion matrix, precision, recall, F1, accuracy, and rank-based
  AUC; KYA verdicts as labels, purchase-policy rejections excluded as
  ambiguous and counted; records_from_audit pairs audit log entries
  with model scores by credential id; POST /benchmark endpoint;
  demo.py step 11; 23 new tests, 111 total green).

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
   linking back to the AgentRisk work (DONE 2026-11-05: kya/benchmark.py,
   score_model, records_from_audit, POST /benchmark, demo step 11;
   23 new tests, 111 total green).
- Per-seed AgentRisk scoring with confidence intervals (DONE
  2026-11-09: kya/agentrisk.py, score_agentrisk_policy_per_seed
  with summarize_values, Student's t intervals at 0.90/0.95/0.99
  clipped to [0, 1], per-metric defined-seed counts, bundled
  per-seed snapshot kya/agentrisk_per_seed_results.csv, 495 rows
  from results/main.csv in the AgentRisk repo; Legacy and AgentGate
  headlines are identical on all 5 seeds at threshold 0.5, so
  their 95 percent intervals have zero width; demo step 13; 16
  new tests, 159 total green).
7. AgentRisk link-up (DONE 2026-11-07: kya/agentrisk.py,
   records_from_agentrisk / load_agentrisk_csv /
   score_agentrisk_policy, class-to-KYA-reason mapping for all 9
   AgentRisk session classes, bundled 18-row snapshot of the
   RishabhPande/agentrisk results file; Legacy scores precision 0.75,
   AUC 0.89 and AgentGate precision 1.00, AUC 1.00 on the snapshot,
   reproducing the paper headline; demo step 12; 24 new tests,
   135 total green). Note: the published dataset is a results file
   (mean decline rate per policy x class), not per-case JSON, so
   records are class-level cells and the metrics measure class
   separation, not per-transaction discrimination.
8. AgentRisk benchmark endpoint (DONE 2026-11-11: POST
   /benchmark/agentrisk in service/app.py; policy scored on
   caller-supplied rows or the bundled snapshot, per_seed mode with
   confidence intervals from the bundled per-seed snapshot, seed
   filter for single scoring, all validation failures as 422;
   16 new tests, 192 total green).

## Naming and license (suggested)
- Repo: `know-your-agent` (public)
- License: MIT (widest adoption for a toolkit)
- Language: Python (matches his stack; cryptography lib for Ed25519)
