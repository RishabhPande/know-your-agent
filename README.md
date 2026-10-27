# Know Your Agent (KYA)

AI agents now shop, book, and pay on behalf of humans, but fraud systems still
see only a human account behind the transaction. When an agent acts, nobody can
answer three questions cryptographically: which agent is this, who authorized
it, and what exactly is it allowed to do?

Know Your Agent (KYA) gives every agent transaction a verifiable identity:
scoped, session-limited, and revocable. A credential binds an agent ID to a
human principal, a scope, and a session window, and is signed with Ed25519.
Verification fails closed: anything unverifiable is rejected, with a reason
code, instead of raising or passing silently.

## Quickstart

Runs in minutes. No servers, no accounts, no real money.

```bash
git clone https://github.com/RishabhPande/know-your-agent.git
cd know-your-agent
pip install -r requirements.txt
python demo.py
```

Expected output:

```
Issued credential for agent-shopper-01 (principal user-123).
Scope: up to $50 in electronics. Session: 1 hour.

1. $30 electronics purchase: ACCEPTED (allowed)
2. $500 electronics purchase: REJECTED (amount_exceeds_scope)
3. $30 groceries purchase: REJECTED (category_not_allowed)
4. $30 electronics purchase after revocation: REJECTED (revoked)
5. Tampered credential (agent id changed): REJECTED (bad_signature)
```

Run the tests with:

```bash
python -m pytest tests/ -q
```

## Credential format

A credential is plain JSON with three keys: the payload, a base64url Ed25519
signature over the canonical payload (sorted keys, no whitespace), and the
algorithm name.

```json
{
  "payload": {
    "version": 1,
    "credential_id": "9f2c... (unique id; the revocation handle)",
    "agent_id": "agent-shopper-01",
    "principal": "user-123",
    "issuer": "kya",
    "scope": {"max_amount_usd": 50.0, "categories": ["electronics"]},
    "not_before": "2026-10-27T00:00:00Z",
    "not_after": "2026-10-27T01:00:00Z",
    "issued_at": "2026-10-27T00:00:00Z"
  },
  "signature": "BASE64URL_ED25519_SIGNATURE",
  "algorithm": "Ed25519"
}
```

Field notes:

- `credential_id` is unique per credential and serves as the revocation
  handle for later iterations.
- `scope` describes what the agent may do. v0.1 supports purchase scope
  (`max_amount_usd`, `categories`); the shape is extensible.
- Times are UTC ISO 8601 strings. The session window is enforced at
  verification time.

## API

```python
from kya import (
    authorize_purchase,
    generate_keypair,
    issue_credential,
    verify_credential,
)

private_key, public_key = generate_keypair()
credential = issue_credential(
    private_key,
    agent_id="agent-shopper-01",
    principal="user-123",
    scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
    not_before="2026-10-27T00:00:00Z",
    not_after="2026-10-27T01:00:00Z",
)

ok, reason = verify_credential(public_key, credential)
ok, reason = authorize_purchase(public_key, credential, 30.0, "electronics")
```

`verify_credential` returns `(True, "ok")` or `(False, reason)`, checked in
this order: `malformed`, `unsupported_algorithm`, `bad_signature`,
`revoked`, `expired` / `not_yet_valid`, `bad_scope`. It also accepts an
optional `revoked_ids` set; a credential whose id is in that set is
rejected as `revoked`. In v0.1 the caller manages that set; full
revocation management arrives in a later iteration (see below).

`authorize_purchase` combines verification with a scope check and returns
`(True, "allowed")` only when both pass, otherwise the verification reason
or a scope reason: `amount_exceeds_scope`, `category_not_allowed`,
`no_purchase_scope`, `invalid_amount`.

## Security notes

- Fail closed, everywhere: unverifiable input is rejected, never accepted
  on a best effort basis.
- Demo keys are generated in memory and discarded on exit. Never reuse demo
  keys for real authorization, and never commit private keys to a repo.
- Ed25519 only. There is no password, token, or shared-secret path.
- Everything runs offline and deterministically; there is no network call
  in the issue, verify, or authorize path.

## What comes next

v0.1 is the core: credential model, issue and verify, purchase policy, demo,
and tests. The next iterations, in order:

1. Delegation chains: an agent delegates a subset of its scope to a
   sub-agent; verification walks the chain and enforces that scope only
   narrows, never widens.
2. Revocation management: a maintained revocation list with a revoke API
   and verification-time lookup.
3. Audit trail: a signed, append-only log of issuance, verification, and
   revocation, so a disputed transaction can be reconstructed.
4. FastAPI demo service: a verify endpoint plus a tiny merchant checkout
   example.
5. Benchmark hook: score a fraud model on agent traffic using KYA verdicts
   as labels.

## License

MIT. See LICENSE.
