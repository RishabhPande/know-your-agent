"""End-to-end demo: a shopping agent with a Know Your Agent credential.

Run: python demo.py

The demo issues a credential for a shopping agent (principal: a human user,
scope: purchases up to $50 in electronics, session: 1 hour), then runs five
checks against it. No servers, no accounts, no real money. Keys are generated
in memory and discarded when the demo exits.
"""

from datetime import datetime, timedelta, timezone

from kya import (
    RevocationList,
    authorize_purchase,
    authorize_purchase_chain,
    delegate_credential,
    generate_keypair,
    issue_credential,
    verify_chain,
    verify_credential,
)


def verdict(ok, reason):
    return "ACCEPTED (%s)" % reason if ok else "REJECTED (%s)" % reason


def main():
    now = datetime.now(timezone.utc)
    private_key, public_key = generate_keypair()

    credential = issue_credential(
        private_key,
        agent_id="agent-shopper-01",
        principal="user-123",
        scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    print("Issued credential for agent-shopper-01 (principal user-123).")
    print("Scope: up to $50 in electronics. Session: 1 hour.")
    print()

    ok, reason = authorize_purchase(public_key, credential, 30.0, "electronics")
    print("1. $30 electronics purchase: %s" % verdict(ok, reason))

    ok, reason = authorize_purchase(public_key, credential, 500.0, "electronics")
    print("2. $500 electronics purchase: %s" % verdict(ok, reason))

    ok, reason = authorize_purchase(public_key, credential, 30.0, "groceries")
    print("3. $30 groceries purchase: %s" % verdict(ok, reason))

    revocations = RevocationList()
    revocations.revoke_credential(credential, reason="reported stolen")
    ok, reason = authorize_purchase(
        public_key, credential, 30.0, "electronics", revoked_ids=revocations
    )
    print("4. $30 electronics purchase after revocation: %s" % verdict(ok, reason))

    tampered = {
        "payload": dict(credential["payload"], agent_id="agent-impostor-99"),
        "signature": credential["signature"],
        "algorithm": credential["algorithm"],
    }
    ok, reason = verify_credential(public_key, tampered)
    print("5. Tampered credential (agent id changed): %s" % verdict(ok, reason))

    # Delegation: the shopper delegates a narrowed scope ($20, same
    # categories, shorter window) to a sub-agent. The chain verifies, and
    # purchases are checked against the leaf's scope, not the root's.
    delegated = delegate_credential(
        private_key,
        credential,
        agent_id="agent-sub-01",
        scope={"max_amount_usd": 20.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=30),
    )
    ok, reason = verify_chain(public_key, [credential, delegated])
    print("6. Delegated chain (root -> sub-agent, $20): %s" % verdict(ok, reason))

    ok, reason = authorize_purchase_chain(
        public_key, [credential, delegated], 15.0, "electronics"
    )
    print("7. $15 electronics purchase via sub-agent: %s" % verdict(ok, reason))

    ok, reason = authorize_purchase_chain(
        public_key, [credential, delegated], 30.0, "electronics"
    )
    print(
        "8. $30 electronics purchase via sub-agent (over leaf limit): %s"
        % verdict(ok, reason)
    )


if __name__ == "__main__":
    main()
