# Know Your Agent (KYA)

[![Tests](https://github.com/RishabhPande/know-your-agent/actions/workflows/tests.yml/badge.svg)](https://github.com/RishabhPande/know-your-agent/actions/workflows/tests.yml)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/RishabhPande/know-your-agent)

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
6. Delegated chain (root -> sub-agent, $20): ACCEPTED (ok)
7. $15 electronics purchase via sub-agent: ACCEPTED (allowed)
8. $30 electronics purchase via sub-agent (over leaf limit): REJECTED (amount_exceeds_scope)
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
  handle for `RevocationList`.
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
`revoked`, `expired` / `not_yet_valid`, `bad_scope`. It accepts an
optional `revoked_ids` argument: either a plain set of ids or a
`RevocationList` (see below). A credential whose id is revoked is
rejected as `revoked`, even inside its session window, and revocation
beats expiry in the check order.

`authorize_purchase` combines verification with a scope check and returns
`(True, "allowed")` only when both pass, otherwise the verification reason
or a scope reason: `amount_exceeds_scope`, `category_not_allowed`,
`no_purchase_scope`, `invalid_amount`.

## Delegation chains

An agent may delegate a subset of its authority to a sub-agent with
`delegate_credential()`. The delegated credential links back to its parent
via `delegated_from` (parent `credential_id`) and `delegator_agent_id`
(parent `agent_id`), keeps the same principal and issuer, and must narrow
the scope and shrink the session window - `delegate_credential()` raises
`ValueError` on any widening. `verify_chain()` walks `[root, ..., leaf]`
and fails closed: every link must verify individually, links must connect,
the principal must not change, windows may only shrink, and scopes may
only narrow, with reasons `bad_chain`, `principal_mismatch`,
`window_widened`, and `scope_widened`. `authorize_purchase_chain()`
verifies the chain and checks the purchase against the leaf's scope, so a
$30 purchase that the root allows is still rejected when the leaf's limit
is $20.

```python
from kya import delegate_credential, verify_chain, authorize_purchase_chain

delegated = delegate_credential(
    private_key,
    credential,
    agent_id="agent-sub-01",
    scope={"max_amount_usd": 20.0, "categories": ["electronics"]},
    not_before="2026-10-27T00:00:00Z",
    not_after="2026-10-27T00:30:00Z",
)
ok, reason = verify_chain(public_key, [credential, delegated])
ok, reason = authorize_purchase_chain(
    public_key, [credential, delegated], 15.0, "electronics"
)
```

## Revocation management

`RevocationList` owns the revoked ids, so no caller has to maintain a set
by hand. Revoke by id or straight from a credential, pass the list itself
to any verify or authorize call, and save it to disk as JSON when it
needs to survive a restart. Revocation is permanent: there is no unrevoke,
so a mistaken revocation is fixed by issuing a fresh credential, not by
resurrecting the old one. Revoking any link in a delegation chain fails
the whole chain, root or leaf.

```python
from kya import RevocationList, verify_credential

revocations = RevocationList()
revocations.revoke_credential(credential, reason="reported stolen")
ok, reason = verify_credential(public_key, credential, revoked_ids=revocations)
# (False, "revoked")

saved = revocations.to_json()
restored = RevocationList.from_json(saved)
assert restored.is_revoked(credential["payload"]["credential_id"])
```

Re-revoking an id is a harmless no-op that returns `False` and keeps the
original entry, so repeated calls never rewrite history. Loading
validates strictly and raises `ValueError` on a bad version, a duplicate
id, or a malformed entry, instead of silently dropping entries.

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
and tests. Delegation chains and revocation management shipped next (see
above). The remaining iterations, in order:

1. Audit trail: a signed, append-only log of issuance, verification, and
   revocation, so a disputed transaction can be reconstructed.
2. FastAPI demo service: a verify endpoint plus a tiny merchant checkout
   example.
3. Benchmark hook: score a fraud model on agent traffic using KYA verdicts
   as labels.

## License

MIT. See LICENSE.
