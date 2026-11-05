"""Tests for the benchmark hook (kya/benchmark.py) and its service endpoint."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from kya import (
    AuditLog,
    generate_keypair,
    issue_credential,
    verify_credential,
)
from kya.benchmark import (
    BENCHMARK_VERSION,
    label_for_reason,
    make_record,
    records_from_audit,
    result_from_json,
    result_to_json,
    score_model,
)
from service.app import create_app


def perfect_records():
    # A model that scores every fraud attempt high and every
    # legitimate transaction low.
    return [
        make_record(0.95, "revoked"),
        make_record(0.9, "bad_signature"),
        make_record(0.85, "expired"),
        make_record(0.1, "ok"),
        make_record(0.05, "allowed"),
        make_record(0.2, "ok"),
    ]


def test_label_for_reason_legitimate():
    assert label_for_reason("ok") == 0
    assert label_for_reason("allowed") == 0


def test_label_for_reason_fraud():
    for reason in (
        "revoked",
        "bad_signature",
        "expired",
        "not_yet_valid",
        "bad_scope",
        "malformed",
        "unsupported_algorithm",
        "bad_chain",
        "principal_mismatch",
        "scope_widened",
        "window_widened",
    ):
        assert label_for_reason(reason) == 1


def test_label_for_reason_ambiguous_is_none():
    for reason in (
        "amount_exceeds_scope",
        "category_not_allowed",
        "no_purchase_scope",
        "invalid_amount",
    ):
        assert label_for_reason(reason) is None


def test_label_for_reason_unknown_raises():
    with pytest.raises(ValueError):
        label_for_reason("definitely_not_a_reason")
    with pytest.raises(ValueError):
        label_for_reason("")


def test_make_record_validates_score():
    with pytest.raises(ValueError):
        make_record(1.5, "ok")
    with pytest.raises(ValueError):
        make_record(-0.1, "ok")
    with pytest.raises(ValueError):
        make_record(float("nan"), "ok")
    with pytest.raises(ValueError):
        make_record("high", "ok")
    with pytest.raises(ValueError):
        make_record(True, "ok")


def test_make_record_keeps_optional_ids():
    record = make_record(0.4, "ok", credential_id="cred-1", agent_id="agent-1")
    assert record["credential_id"] == "cred-1"
    assert record["agent_id"] == "agent-1"
    assert record["model_score"] == 0.4


def test_score_perfect_model():
    result = score_model(perfect_records())
    assert result["tp"] == 3
    assert result["tn"] == 3
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["accuracy"] == 1.0
    assert result["auc"] == 1.0
    assert result["n_scored"] == 6
    assert result["n_excluded_ambiguous"] == 0
    assert result["base_rate"] == 0.5


def test_score_worst_model_is_zero():
    records = [
        make_record(0.05, "revoked"),
        make_record(0.1, "bad_signature"),
        make_record(0.95, "ok"),
        make_record(0.9, "allowed"),
    ]
    result = score_model(records)
    assert result["tp"] == 0
    assert result["fn"] == 2
    assert result["fp"] == 2
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] is None
    assert result["auc"] == 0.0


def test_score_threshold_changes_predictions():
    records = [
        make_record(0.6, "revoked"),
        make_record(0.4, "ok"),
    ]
    low = score_model(records, threshold=0.5)
    assert (low["tp"], low["tn"]) == (1, 1)
    high = score_model(records, threshold=0.7)
    assert (high["fn"], high["tn"]) == (1, 1)
    assert high["recall"] == 0.0


def test_score_threshold_at_boundary_counts_as_fraud():
    result = score_model([make_record(0.5, "revoked")], threshold=0.5)
    assert result["tp"] == 1


def test_score_auc_tie_is_half():
    records = [
        make_record(0.5, "revoked"),
        make_record(0.5, "ok"),
    ]
    assert score_model(records)["auc"] == 0.5


def test_score_auc_none_with_one_class():
    result = score_model([make_record(0.9, "ok"), make_record(0.1, "ok")])
    assert result["auc"] is None
    assert result["recall"] is None
    assert result["precision"] == 0.0
    assert result["base_rate"] == 0.0


def test_score_empty_records():
    result = score_model([])
    assert result["n_records"] == 0
    assert result["n_scored"] == 0
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None
    assert result["accuracy"] is None
    assert result["auc"] is None
    assert result["base_rate"] is None


def test_score_excludes_ambiguous_records():
    records = perfect_records() + [
        make_record(0.99, "amount_exceeds_scope"),
        make_record(0.01, "category_not_allowed"),
    ]
    result = score_model(records)
    assert result["n_records"] == 8
    assert result["n_scored"] == 6
    assert result["n_excluded_ambiguous"] == 2
    assert result["precision"] == 1.0
    assert result["by_reason"]["amount_exceeds_scope"]["n"] == 1
    assert result["by_reason"]["amount_exceeds_scope"]["mean_model_score"] == 0.99


def test_score_by_reason_breakdown():
    result = score_model(
        [
            make_record(0.9, "revoked"),
            make_record(0.7, "revoked"),
            make_record(0.1, "ok"),
        ]
    )
    assert result["by_reason"]["revoked"]["n"] == 2
    assert result["by_reason"]["revoked"]["mean_model_score"] == 0.8
    assert result["by_reason"]["ok"]["mean_model_score"] == 0.1


def test_score_rejects_bad_records():
    with pytest.raises(ValueError):
        score_model([{"model_score": 0.5}])
    with pytest.raises(ValueError):
        score_model([{"model_score": 0.5, "kya_reason": "nope"}])
    with pytest.raises(ValueError):
        score_model("not a list")
    with pytest.raises(ValueError):
        score_model(perfect_records(), threshold=1.5)


def test_result_json_round_trip():
    result = score_model(perfect_records())
    loaded = result_from_json(result_to_json(result))
    assert loaded == result
    assert loaded["version"] == BENCHMARK_VERSION
    json.loads(result_to_json(result))


def test_result_from_json_rejects_bad_versions():
    with pytest.raises(ValueError):
        result_from_json('{"version": 99}')
    with pytest.raises(ValueError):
        result_from_json("not json")


def test_records_from_audit_pairs_scores_by_credential_id():
    private_key, public_key = generate_keypair()
    now = datetime.now(timezone.utc)
    audit = AuditLog(private_key)
    good = issue_credential(
        private_key,
        agent_id="agent-1",
        principal="user-1",
        scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    audit.record_issued(good)
    ok, reason = verify_credential(public_key, good)
    audit.record_verified(good, ok, reason)
    bad = issue_credential(
        private_key,
        agent_id="agent-2",
        principal="user-1",
        scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    tampered = {
        "payload": dict(bad["payload"], agent_id="agent-impostor"),
        "signature": bad["signature"],
        "algorithm": bad["algorithm"],
    }
    ok, reason = verify_credential(public_key, tampered)
    audit.record_verified(tampered, ok, reason)

    records, counts = records_from_audit(
        audit.entries(),
        {
            good["payload"]["credential_id"]: 0.1,
            tampered["payload"]["credential_id"]: 0.95,
        },
    )
    assert counts["n_verified"] == 2
    assert counts["n_scored"] == 2
    assert counts["n_no_model_score"] == 0
    assert counts["n_skipped_kinds"] == 1
    result = score_model(records)
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["auc"] == 1.0


def test_records_from_audit_counts_missing_scores():
    private_key, _public_key = generate_keypair()
    now = datetime.now(timezone.utc)
    audit = AuditLog(private_key)
    credential = issue_credential(
        private_key,
        agent_id="agent-1",
        principal="user-1",
        scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    audit.record_issued(credential)
    audit.record_verified(credential, True, "ok")
    records, counts = records_from_audit(audit.entries(), {})
    assert records == []
    assert counts["n_verified"] == 1
    assert counts["n_no_model_score"] == 1
    assert counts["n_skipped_kinds"] == 1


def test_records_from_audit_rejects_unknown_outcome():
    entries = [
        {
            "kind": "verified",
            "credential_id": "cred-1",
            "agent_id": "agent-1",
            "principal": "user-1",
            "outcome": "mystery",
        }
    ]
    with pytest.raises(ValueError):
        records_from_audit(entries, {"cred-1": 0.5})


def test_benchmark_endpoint_scores_records():
    _private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    response = client.post(
        "/benchmark",
        json={"records": [dict(r) for r in perfect_records()], "threshold": 0.5},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["precision"] == 1.0
    assert body["auc"] == 1.0
    assert body["n_scored"] == 6


def test_benchmark_endpoint_rejects_bad_record():
    _private_key, public_key = generate_keypair()
    client = TestClient(create_app(public_key))
    response = client.post(
        "/benchmark",
        json={"records": [{"model_score": 2.0, "kya_reason": "ok"}]},
    )
    assert response.status_code == 422
    response = client.post(
        "/benchmark",
        json={"records": [{"model_score": 0.5, "kya_reason": "nope"}]},
    )
    assert response.status_code == 422
    response = client.post("/benchmark", json={"records": [], "threshold": 1.5})
    assert response.status_code == 422
