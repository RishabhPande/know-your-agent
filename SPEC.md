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
- Backlog complete as of 2026-11-09 (see below), replay
  protection shipped 2026-11-19, and shared persistent state
  shipped 2026-11-21 (see below). No candidate is committed for
  the next loop yet; a shared backend for stores on different
  machines is the natural follow-on and stays uncommitted until
  it is scoped.

## Shipped since v0.1
- Shared persistent state (DONE 2026-11-21: kya/shared.py,
  FileRevocationList and FileReplayStore with the in-memory
  stores' exact behaviour and JSON format; every read reloads
  from the file and every mutation rewrites it atomically under
  an exclusive advisory lock on a sibling .lock file, so
  processes sharing a path agree and state survives restarts; a
  damaged file raises ValueError instead of starting empty, a
  missing file starts empty; create_app gains revocations_path
  and replay_store_path, which cannot be combined with a store
  instance for the same state; demo step 17; 19 new tests, 297
  total green. Honest limit: the advisory lock covers one
  machine's filesystem, not stores on different machines).
- Replay protection (DONE 2026-11-19: kya/replay.py, ReplayStore
  keyed by (credential_id, presentation_id) with strict JSON
  persistence in the RevocationList pattern and a caller-cutoff
  prune; authorize_purchase and authorize_purchase_chain accept
  replay_store and presentation_id, consume the id only on an
  allowed purchase, and reject a repeat as replay and a missing id
  as missing_presentation_id; plain verify_credential never
  consumes an id; evaluate_corpus gains replay_protection=True,
  presenting each transaction under its own tx id and a replay
  transaction under its source tx id, which catches all 100
  in-window replays on the default corpus (attacks 1950/1950, no
  other verdict changes); the service accepts presentation_id on
  POST /checkout and POST /checkout-chain (keyed by the leaf for a
  chain, per-app store unless shared) and replay_protection on
  POST /evaluate; demo step 16; 20 new tests, 275 total green.
  Honest limit: unshared stores do not share replay state, so a
  replay aimed at a different process still passes).
- Gate evaluation endpoint (DONE 2026-11-17: POST /evaluate in
  service/app.py; runs evaluate_corpus over a caller-supplied corpus
  in {"corpus": {...}} form, or over a corpus the service builds
  itself from {"seed": ..., "counts": {...}}, or over the default
  corpus when neither is sent; corpus cannot be combined with seed
  or counts; an optional revoked_ids list overrides the corpus
  revocation state, so an empty list measures what revocation is
  worth; every library ValueError is a 422, matching POST
  /benchmark, and a wrong request shape is a 422 from validation;
  the endpoint is an evaluation harness, not an authorization path:
  it judges against the issuer key the corpus carries, not the
  service trusted key, and touches neither the service revocation
  list nor the audit log, which the tests pin down; 19 new tests,
  255 total green).
- Gate evaluation helper (DONE 2026-11-15: kya/evaluate.py,
  evaluate_corpus with evaluation_to_json and evaluation_from_json;
  runs the real gate over a built corpus at each transaction's own
  timestamp, with the corpus issuer key and revocation state unless
  overridden; per-class and per-family accepted, rejected, and
  correct counts with correct rates, attack catch rates, per-class
  reason tallies, full verdict list, and missed_attack_ids and
  false_reject_ids naming the misses; strict ValueError validation
  on malformed corpora, duplicate transaction ids, unknown kinds,
  and unparseable timestamps; unknown classes group by label; demo
  step 15; the corpus tests now delegate to it instead of their own
  gate loop; 16 new tests, 236 total green. Default corpus headline:
  legitimate 2500/2500 accepted, policy 650/650 rejected, attacks
  1850/1950 caught, every miss an in-window replay).
- Seeded evaluation corpus (DONE 2026-11-13: kya/corpus.py,
  build_corpus and corpus_to_json; deterministic, byte-identical
  rebuild from a seed; 5,100 transactions in 20 classes at the
  default seed 20261112: 2,500 legitimate, 650 policy violations
  with label None, 1,950 attacks across 15 classes including
  in-window replay, which the gate accepts and which is reported
  as a known v0.1 limitation (no nonce); counts validated as
  non-negative ints, unknown classes raise ValueError; demo step
  14; 13 corpus tests, 220 total green).
- Delegated checkout endpoint (DONE 2026-11-13 via PR #10:
  POST /checkout-chain in service/app.py, authorizing a purchase
  against the leaf of a delegation chain over HTTP with the same
  fail-closed reasons as the library, leaf audit recording when a
  log is configured; 15 new tests, 217 total green on sync).
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
9. Delegated checkout endpoint (DONE 2026-11-13 via PR #10: POST
   /checkout-chain in service/app.py; whole-chain verification,
   leaf scope enforcement, revoked-link rejection, leaf audit
   recording; 15 new tests, 217 total green on sync).
10. Seeded evaluation corpus (DONE 2026-11-13: kya/corpus.py,
    build_corpus / corpus_to_json, 20 classes, deterministic
    rebuild, in-window replay measured as a known limitation;
    demo step 14; 13 corpus tests, 220 total green).
11. Gate evaluation helper (DONE 2026-11-15: kya/evaluate.py,
    evaluate_corpus / evaluation_to_json / evaluation_from_json,
    per-class verdicts and catch rates over a built corpus, misses
    named by transaction id, corpus tests migrated onto it;
    demo step 15; 16 new tests, 236 total green).
12. Gate evaluation endpoint (DONE 2026-11-17: POST /evaluate in
    service/app.py; caller-supplied corpus, or server-built from
    seed and counts, or the default corpus; revoked_ids override;
    all failures as 422; evaluation harness only, service
    revocations and audit untouched; 19 new tests, 255 total
    green).
13. Replay protection (DONE 2026-11-19: kya/replay.py, ReplayStore
    with (credential_id, presentation_id) keys, strict JSON
    persistence, and prune; replay_store and presentation_id on
    authorize_purchase and authorize_purchase_chain, consumed only
    on an allowed purchase, reasons replay and
    missing_presentation_id; evaluate_corpus replay_protection
    mode presenting replays under their source transaction id,
    catching all 100 default-corpus in-window replays with no
    other verdict changed; presentation_id on POST /checkout and
    POST /checkout-chain and replay_protection on POST /evaluate;
    demo step 16; 20 new tests, 275 total green).
14. Shared persistent state (DONE 2026-11-21: kya/shared.py,
    FileRevocationList and FileReplayStore, reload on every read
    and atomic locked rewrite on every mutation, in-memory JSON
    format on disk, fail closed on a damaged file;
    revocations_path and replay_store_path on create_app; demo
    step 17; 19 new tests, 297 total green).

## Naming and license (suggested)
- Repo: `know-your-agent` (public)
- License: MIT (widest adoption for a toolkit)
- Language: Python (matches his stack; cryptography lib for Ed25519)
