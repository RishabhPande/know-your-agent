"""Tests for the Know Your Agent FastAPI demo service (service/app.py)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from kya import (
    AuditLog,
    RevocationList,
    authorize_purchase,
    bundled_per_seed_results_path,
    bundled_results_path,
    delegate_credential,
    generate_keypair,
    issue_credential,
    load_agentrisk_csv,
    score_agentrisk_policy,
    score_agentrisk_policy_per_seed,
)
from service.app import create_app


def make_credential(private_key, **overrides):
    now = datetime.now(timezone.utc)
    args = {
        "agent_id": "agent-shopper-01",
        "principal": "user-123",
        "scope": {"max_amount_usd": 50.0, "categories": ["electronics"]},
        "not_before": now - timedelta(minutes=5),
        "not_after": now + timedelta(hours=1),
    }
    args.update(overrides)
    return issue_credential(private_key, **args)


@pytest.fixture()
def setup():
    private_key, public_key = generate_keypair()
    revocations = RevocationList()
    audit = AuditLog(private_key)
    app = create_app(public_key, revocations=revocations, audit=audit)
    return {
        "private_key": private_key,
        "public_key": public_key,
        "revocations": revocations,
        "audit": audit,
        "client": TestClient(app),
    }


def test_health(setup):
    response = setup["client"].get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_verify_accepts_valid_credential(setup):
    credential = make_credential(setup["private_key"])
    response = setup["client"].post("/verify", json={"credential": credential})
    assert response.status_code == 200
    assert response.json() == {"ok": True, "reason": "ok"}


def test_verify_rejects_tampered_credential(setup):
    credential = make_credential(setup["private_key"])
    tampered = {
        "payload": dict(credential["payload"], agent_id="agent-impostor-99"),
        "signature": credential["signature"],
        "algorithm": credential["algorithm"],
    }
    response = setup["client"].post("/verify", json={"credential": tampered})
    assert response.status_code == 200
    assert response.json() == {"ok": False, "reason": "bad_signature"}


def test_verify_rejects_malformed_credential_without_crashing(setup):
    response = setup["client"].post("/verify", json={"credential": {}})
    assert response.status_code == 200
    assert response.json() == {"ok": False, "reason": "malformed"}


def test_verify_rejects_non_object_credential_at_validation(setup):
    # A list is not a credential object at all. Validation rejects it
    # with 422, which is still a rejection, never an acceptance.
    response = setup["client"].post("/verify", json={"credential": ["nope"]})
    assert response.status_code == 422


def test_verify_rejects_expired_credential(setup):
    now = datetime.now(timezone.utc)
    credential = make_credential(
        setup["private_key"],
        not_before=now - timedelta(hours=2),
        not_after=now - timedelta(hours=1),
    )
    response = setup["client"].post("/verify", json={"credential": credential})
    assert response.json() == {"ok": False, "reason": "expired"}


def test_verify_chain_accepts_valid_chain(setup):
    now = datetime.now(timezone.utc)
    root = make_credential(setup["private_key"])
    leaf = delegate_credential(
        setup["private_key"],
        root,
        agent_id="agent-sub-01",
        scope={"max_amount_usd": 20.0, "categories": ["electronics"]},
        not_before=now,
        not_after=now + timedelta(minutes=30),
    )
    response = setup["client"].post(
        "/verify-chain", json={"chain": [root, leaf]}
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "reason": "ok"}


def test_verify_chain_rejects_broken_link(setup):
    root = make_credential(setup["private_key"])
    leaf = dict(root)
    leaf = {
        "payload": dict(root["payload"], agent_id="agent-sub-01"),
        "signature": root["signature"],
        "algorithm": root["algorithm"],
    }
    response = setup["client"].post(
        "/verify-chain", json={"chain": [root, leaf]}
    )
    assert response.json()["ok"] is False


def test_checkout_accepts_in_scope_purchase(setup):
    credential = make_credential(setup["private_key"])
    response = setup["client"].post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 30.0,
            "category": "electronics",
        },
    )
    assert response.status_code == 200
    assert response.json() == {"accepted": True, "reason": "allowed"}


def test_checkout_rejects_over_limit_and_wrong_category(setup):
    credential = make_credential(setup["private_key"])
    client = setup["client"]
    over = client.post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 500.0,
            "category": "electronics",
        },
    )
    assert over.json() == {
        "accepted": False,
        "reason": "amount_exceeds_scope",
    }
    wrong_category = client.post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 30.0,
            "category": "groceries",
        },
    )
    assert wrong_category.json() == {
        "accepted": False,
        "reason": "category_not_allowed",
    }


def test_checkout_rejects_invalid_amount(setup):
    credential = make_credential(setup["private_key"])
    response = setup["client"].post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 0,
            "category": "electronics",
        },
    )
    assert response.json() == {"accepted": False, "reason": "invalid_amount"}


def test_revoke_by_id_then_verify_and_checkout_fail(setup):
    credential = make_credential(setup["private_key"])
    client = setup["client"]
    credential_id = credential["payload"]["credential_id"]

    revoked = client.post(
        "/revoke", json={"credential_id": credential_id, "reason": "stolen"}
    )
    assert revoked.status_code == 200
    assert revoked.json() == {"revoked": True, "credential_id": credential_id}

    # Re-revoking is a harmless no-op, matching RevocationList.
    again = client.post("/revoke", json={"credential_id": credential_id})
    assert again.json()["revoked"] is False

    verify = client.post("/verify", json={"credential": credential})
    assert verify.json() == {"ok": False, "reason": "revoked"}
    checkout = client.post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 30.0,
            "category": "electronics",
        },
    )
    assert checkout.json() == {"accepted": False, "reason": "revoked"}


def test_revoke_with_full_credential_records_audit(setup):
    credential = make_credential(setup["private_key"])
    client = setup["client"]
    response = client.post(
        "/revoke",
        json={"credential": credential, "reason": "reported stolen"},
    )
    assert response.json()["revoked"] is True
    audit = client.get("/audit").json()
    assert audit["ok"] is True
    kinds = [entry["kind"] for entry in audit["entries"]]
    assert "revoked" in kinds


def test_revoke_needs_credential_or_id(setup):
    response = setup["client"].post("/revoke", json={})
    assert response.status_code == 422


def test_checkout_is_audited_and_audit_verifies(setup):
    credential = make_credential(setup["private_key"])
    client = setup["client"]
    client.post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 30.0,
            "category": "electronics",
        },
    )
    client.post(
        "/checkout",
        json={
            "credential": credential,
            "amount_usd": 500.0,
            "category": "electronics",
        },
    )
    audit = client.get("/audit").json()
    assert audit["ok"] is True
    assert audit["reason"] == "ok"
    outcomes = [entry["outcome"] for entry in audit["entries"]]
    assert outcomes == ["allowed", "amount_exceeds_scope"]


def test_audit_endpoint_404_without_audit_log():
    _, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    response = client.get("/audit")
    assert response.status_code == 404


def test_apps_do_not_share_revocation_state():
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    first = TestClient(create_app(public_key))
    second = TestClient(create_app(public_key))
    first.post(
        "/revoke",
        json={"credential_id": credential["payload"]["credential_id"]},
    )
    assert first.post("/verify", json={"credential": credential}).json()[
        "reason"
    ] == "revoked"
    assert second.post("/verify", json={"credential": credential}).json() == {
        "ok": True,
        "reason": "ok",
    }


def test_library_and_service_agree():
    # The service must never disagree with the library it wraps.
    private_key, public_key = generate_keypair()
    credential = make_credential(private_key)
    client = TestClient(create_app(public_key))
    for amount, category in (
        (30.0, "electronics"),
        (500.0, "electronics"),
        (30.0, "groceries"),
    ):
        expected_ok, expected_reason = authorize_purchase(
            public_key, credential, amount, category
        )
        got = client.post(
            "/checkout",
            json={
                "credential": credential,
                "amount_usd": amount,
                "category": category,
            },
        ).json()
        assert got == {"accepted": expected_ok, "reason": expected_reason}


@pytest.mark.parametrize("body", [
    {"credential_id": ""},
    {"credential": {"payload": {"credential_id": ""}}},
])
def test_revoke_rejects_empty_id_without_state_or_audit_changes(setup, body):
    credential = make_credential(setup["private_key"])
    setup["audit"].record_issued(credential)
    before_revocations = setup["revocations"].to_dict()
    before_audit = setup["audit"].to_dict()

    response = setup["client"].post("/revoke", json=body)

    assert response.status_code == 422
    assert response.json() == {"detail": "credential_id must be a non-empty string"}
    assert setup["revocations"].to_dict() == before_revocations
    assert setup["audit"].to_dict() == before_audit
    valid = setup["client"].post("/verify", json={"credential": credential})
    assert valid.json() == {"ok": True, "reason": "ok"}


def test_revoke_can_succeed_after_rejected_empty_id(setup):
    credential = make_credential(setup["private_key"])
    rejected = setup["client"].post("/revoke", json={"credential_id": ""})
    assert rejected.status_code == 422
    accepted = setup["client"].post("/revoke", json={"credential": credential})
    assert accepted.status_code == 200
    assert accepted.json()["revoked"] is True
    assert len(setup["revocations"]) == 1
    assert len(setup["audit"]) == 1
    assert setup["audit"].verify(setup["public_key"]) == (True, "ok")


def agentrisk_client():
    _private_key, public_key = generate_keypair()
    return TestClient(create_app(public_key))


def test_benchmark_agentrisk_bundled_legacy_reproduces_headline():
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "Legacy"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["counts"] == {
        "policy": "Legacy",
        "n_rows": 18,
        "n_policy_rows": 9,
        "n_records": 9,
    }
    result = body["result"]
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (6, 2, 1, 0)
    assert result["precision"] == pytest.approx(0.75)
    assert result["recall"] == pytest.approx(1.0)
    assert result["auc"] == pytest.approx(16 / 18)


def test_benchmark_agentrisk_bundled_agentgate_separates_cleanly():
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "AgentGate"}
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["precision"] == pytest.approx(1.0)
    assert result["auc"] == pytest.approx(1.0)


def test_benchmark_agentrisk_explicit_rows_agree_with_library():
    rows = load_agentrisk_csv(bundled_results_path())
    _records, counts, result = score_agentrisk_policy(rows, "Legacy")
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "Legacy", "rows": rows}
    )
    assert response.status_code == 200
    assert response.json() == {"counts": counts, "result": result}


def test_benchmark_agentrisk_threshold_passes_through():
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "Legacy", "threshold": 0.9}
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (5, 2, 1, 1)


def test_benchmark_agentrisk_seed_filter_on_explicit_rows():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    _records, counts, result = score_agentrisk_policy(rows, "Legacy", seed=0)
    response = agentrisk_client().post(
        "/benchmark/agentrisk",
        json={"policy": "Legacy", "rows": rows, "seed": 0},
    )
    assert response.status_code == 200
    assert response.json() == {"counts": counts, "result": result}
    assert counts["n_records"] == 9


def test_benchmark_agentrisk_per_seed_bundled_agrees_with_library():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "Legacy", "per_seed": True}
    )
    assert response.status_code == 200
    assert response.json() == {"per_seed": per_seed, "summary": summary}
    assert summary["n_seeds"] == 5
    assert summary["metrics"]["auc"]["mean"] == pytest.approx(16 / 18)


def test_benchmark_agentrisk_per_seed_explicit_rows_and_confidence():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    response = agentrisk_client().post(
        "/benchmark/agentrisk",
        json={
            "policy": "AgentGate",
            "rows": rows,
            "per_seed": True,
            "confidence": 0.99,
        },
    )
    assert response.status_code == 200
    summary = response.json()["summary"]
    assert summary["confidence"] == 0.99
    assert summary["metrics"]["auc"]["mean"] == pytest.approx(1.0)


def test_benchmark_agentrisk_unknown_policy_is_422():
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "Nope"}
    )
    assert response.status_code == 422


def test_benchmark_agentrisk_bad_row_is_422():
    client = agentrisk_client()
    unknown_class = client.post(
        "/benchmark/agentrisk",
        json={
            "policy": "Legacy",
            "rows": [{"policy": "Legacy", "class": "XX", "mean_decline_pct": 50.0}],
        },
    )
    assert unknown_class.status_code == 422
    bad_score = client.post(
        "/benchmark/agentrisk",
        json={
            "policy": "Legacy",
            "rows": [{"policy": "Legacy", "class": "AV", "mean_decline_pct": 150.0}],
        },
    )
    assert bad_score.status_code == 422


def test_benchmark_agentrisk_empty_rows_is_422_not_bundled_fallback():
    response = agentrisk_client().post(
        "/benchmark/agentrisk", json={"policy": "Legacy", "rows": []}
    )
    assert response.status_code == 422


def test_benchmark_agentrisk_per_seed_on_means_rows_is_422():
    rows = load_agentrisk_csv(bundled_results_path())
    response = agentrisk_client().post(
        "/benchmark/agentrisk",
        json={"policy": "Legacy", "rows": rows, "per_seed": True},
    )
    assert response.status_code == 422


def test_benchmark_agentrisk_seed_with_per_seed_is_422():
    response = agentrisk_client().post(
        "/benchmark/agentrisk",
        json={"policy": "Legacy", "per_seed": True, "seed": 0},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("body", [
    {"policy": "Legacy", "threshold": 1.5},
    {"policy": "Legacy", "score_column": "bogus"},
    {"policy": "Legacy", "per_seed": True, "confidence": 0.5},
    {"policy": ""},
])
def test_benchmark_agentrisk_bad_options_are_422(body):
    response = agentrisk_client().post("/benchmark/agentrisk", json=body)
    assert response.status_code == 422
