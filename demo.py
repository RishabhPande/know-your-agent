"""End-to-end demo: a shopping agent with a Know Your Agent credential.

Run: python demo.py

The demo issues a credential for a shopping agent (principal: a human user,
scope: purchases up to $50 in electronics, session: 1 hour), then runs five
checks against it. No servers, no accounts, no real money. Keys are generated
in memory and discarded when the demo exits.
"""

from datetime import datetime, timedelta, timezone

from kya import (
    AuditLog,
    RevocationList,
    authorize_purchase,
    authorize_purchase_chain,
    delegate_credential,
    generate_keypair,
    issue_credential,
    records_from_audit,
    score_model,
    verify_audit_entries,
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

    # Audit trail: the issuance, one verification, and the revocation go
    # into a signed, hash-chained log. The demo signs the log with the
    # issuer key for simplicity; a real deployment would use a separate
    # audit key. Tampering with any recorded entry breaks the chain.
    audit = AuditLog(private_key)
    audit.record_issued(credential)
    ok, reason = verify_credential(public_key, credential)
    audit.record_verified(credential, ok, reason)
    audit.record_revoked(credential, reason="reported stolen")
    ok, reason = audit.verify(public_key)
    print("9. Audit log (%d entries) verifies: %s" % (len(audit), verdict(ok, reason)))

    tampered_log = audit.entries()
    tampered_log[0]["outcome"] = "revoked"
    ok, reason = verify_audit_entries(public_key, tampered_log)
    print("10. Tampered audit entry (outcome rewritten): %s" % verdict(ok, reason))

    # Benchmark hook: KYA verdicts are labels for a fraud model. Four
    # fresh credentials stand in for four transactions, and the toy
    # model scores each one from its credential alone (0.1 when the
    # credential verified, 0.9 when it did not). A real model would
    # score from transaction features instead; the point here is the
    # plumbing: verdicts in, precision/recall/AUC out. The over-limit
    # purchase is a policy rejection, not fraud, so it is excluded
    # from the metrics and counted separately.
    bench_audit = AuditLog(private_key)

    def bench_credential(agent_id):
        return issue_credential(
            private_key,
            agent_id=agent_id,
            principal="user-123",
            scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
            not_before=now - timedelta(minutes=5),
            not_after=now + timedelta(hours=1),
        )

    legit = bench_credential("agent-bench-legit")
    ok, reason = verify_credential(public_key, legit)
    bench_audit.record_verified(legit, ok, reason)
    forged = bench_credential("agent-bench-forged")
    forged = {
        "payload": dict(forged["payload"], agent_id="agent-impostor-99"),
        "signature": forged["signature"],
        "algorithm": forged["algorithm"],
    }
    ok, reason = verify_credential(public_key, forged)
    bench_audit.record_verified(forged, ok, reason)
    stolen = bench_credential("agent-bench-stolen")
    revocations.revoke_credential(stolen, reason="reported stolen")
    ok, reason = verify_credential(
        public_key, stolen, revoked_ids=revocations
    )
    bench_audit.record_verified(stolen, ok, reason)
    over_limit = bench_credential("agent-bench-over-limit")
    ok, reason = authorize_purchase(
        public_key, over_limit, 500.0, "electronics"
    )
    bench_audit.record_verified(over_limit, ok, reason)

    model_scores = {}
    for entry in bench_audit.entries():
        if entry["kind"] != "verified":
            continue
        model_scores[entry["credential_id"]] = (
            0.1 if entry["outcome"] == "ok" else 0.9
        )
    records, counts = records_from_audit(bench_audit.entries(), model_scores)
    result = score_model(records)
    print(
        "11. Benchmark (toy model, %d scored, %d ambiguous excluded): "
        "precision %.2f, recall %.2f, AUC %.2f"
        % (
            result["n_scored"],
            result["n_excluded_ambiguous"],
            result["precision"],
            result["recall"],
            result["auc"],
        )
    )

    # AgentRisk link-up: score the two published policies on the
    # AgentRisk results snapshot (18 rows, RishabhPande/agentrisk).
    # Each row is one (policy, class) cell; the policy's decline
    # rate for the class is its score and the class ground truth is
    # the label. Legacy declines legitimate verified agents almost
    # as often as fraud; AgentGate separates them.
    from kya.agentrisk import (
        bundled_results_path,
        load_agentrisk_csv,
        score_agentrisk_policy,
    )

    agentrisk_rows = load_agentrisk_csv(bundled_results_path())
    for policy in ("Legacy", "AgentGate"):
        _records, _counts, policy_result = score_agentrisk_policy(
            agentrisk_rows, policy
        )
        print(
            "12. AgentRisk %s (%d cells): precision %.2f, recall %.2f, "
            "AUC %.2f"
            % (
                policy,
                policy_result["n_scored"],
                policy_result["precision"],
                policy_result["recall"],
                policy_result["auc"],
            )
        )

    # Per-seed scoring: the means file collapses the 5 seeds, so step
    # 12 cannot say whether its headline is stable. Score each seed
    # separately and report the mean AUC with a 95 percent t
    # interval. On this snapshot both policies are identical on
    # every seed at threshold 0.5, so the intervals have zero width:
    # the headline is seed-stable, not a one-seed artifact.
    from kya.agentrisk import (
        bundled_per_seed_results_path,
        score_agentrisk_policy_per_seed,
    )

    per_seed_rows = load_agentrisk_csv(bundled_per_seed_results_path())
    for policy in ("Legacy", "AgentGate"):
        _per_seed, seed_summary = score_agentrisk_policy_per_seed(
            per_seed_rows, policy
        )
        auc = seed_summary["metrics"]["auc"]
        print(
            "13. AgentRisk %s per seed (%d seeds): mean AUC %.2f, "
            "95%% CI [%.2f, %.2f]"
            % (
                policy,
                seed_summary["n_seeds"],
                auc["mean"],
                auc["ci_low"],
                auc["ci_high"],
            )
        )


if __name__ == "__main__":
    main()
