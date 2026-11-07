"""Tests for the AgentRisk link-up (kya/agentrisk.py)."""

import pytest

from kya.agentrisk import (
    CLASS_LABELS,
    bundled_results_path,
    load_agentrisk_csv,
    records_from_agentrisk,
    score_agentrisk_policy,
)
from kya.benchmark import label_for_reason

ALL_CLASSES = ("H", "AU", "AV", "FH", "FB", "FAU", "FAV", "FHJ", "FSP")


def _row(policy, cls, pct, *, legitimate=None, seed=None, score_key="mean_decline_pct"):
    row = {"policy": policy, "class": cls, score_key: pct}
    if legitimate is not None:
        row["is_legitimate"] = legitimate
    if seed is not None:
        row["seed"] = seed
    return row


def test_class_labels_cover_all_nine_classes():
    assert set(CLASS_LABELS) == set(ALL_CLASSES)
    for cls, (reason, label) in CLASS_LABELS.items():
        assert label_for_reason(reason) == label


def test_class_to_reason_mapping():
    assert CLASS_LABELS["H"][0] == "ok"
    assert CLASS_LABELS["AU"][0] == "ok"
    assert CLASS_LABELS["AV"][0] == "ok"
    assert CLASS_LABELS["FH"][0] == "malformed"
    assert CLASS_LABELS["FB"][0] == "malformed"
    assert CLASS_LABELS["FAU"][0] == "bad_signature"
    assert CLASS_LABELS["FSP"][0] == "bad_signature"
    assert CLASS_LABELS["FAV"][0] == "bad_scope"
    assert CLASS_LABELS["FHJ"][0] == "revoked"


def test_bundled_snapshot_loads_18_rows():
    rows = load_agentrisk_csv(bundled_results_path())
    assert len(rows) == 18
    assert sorted({row["policy"] for row in rows}) == ["AgentGate", "Legacy"]
    assert sorted({row["class"] for row in rows}) == sorted(ALL_CLASSES)


def test_legacy_scores_reproduce_the_paper_headline():
    rows = load_agentrisk_csv(bundled_results_path())
    records, counts, result = score_agentrisk_policy(rows, "Legacy")
    assert counts == {
        "policy": "Legacy",
        "n_rows": 18,
        "n_policy_rows": 9,
        "n_records": 9,
    }
    assert len(records) == 9
    # Legacy declines legitimate verified agents (AU, AV) almost as
    # often as fraud, so it flags 2 of 3 legitimate cells.
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (6, 2, 1, 0)
    assert result["precision"] == pytest.approx(0.75)
    assert result["recall"] == pytest.approx(1.0)
    assert result["auc"] == pytest.approx(16 / 18)
    assert result["accuracy"] == pytest.approx(7 / 9)


def test_agentgate_separates_cleanly():
    rows = load_agentrisk_csv(bundled_results_path())
    _records, _counts, result = score_agentrisk_policy(rows, "AgentGate")
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (6, 0, 3, 0)
    assert result["precision"] == pytest.approx(1.0)
    assert result["recall"] == pytest.approx(1.0)
    assert result["auc"] == pytest.approx(1.0)
    assert result["accuracy"] == pytest.approx(1.0)


def test_agentgate_beats_legacy():
    rows = load_agentrisk_csv(bundled_results_path())
    _r, _c, legacy = score_agentrisk_policy(rows, "Legacy")
    _r, _c, gate = score_agentrisk_policy(rows, "AgentGate")
    assert gate["auc"] > legacy["auc"]
    assert gate["precision"] > legacy["precision"]
    assert gate["accuracy"] > legacy["accuracy"]


def test_percent_and_fraction_scores_agree():
    pct_rows = [_row("Legacy", "AV", 94.6), _row("Legacy", "FH", 71.4)]
    frac_rows = [
        _row("Legacy", "AV", 0.946, score_key="decline"),
        _row("Legacy", "FH", 0.714, score_key="decline"),
    ]
    pct_records, _ = records_from_agentrisk(pct_rows, "Legacy")
    frac_records, _ = records_from_agentrisk(frac_rows, "Legacy")
    assert [r["model_score"] for r in pct_records] == pytest.approx(
        [r["model_score"] for r in frac_records]
    )
    assert pct_records[0]["model_score"] == pytest.approx(0.946)


def test_records_are_traceable_to_their_cell():
    rows = load_agentrisk_csv(bundled_results_path())
    records, _ = records_from_agentrisk(rows, "AgentGate")
    by_class = {record["agent_id"]: record for record in records}
    assert by_class["AV"]["credential_id"] == "agentrisk:AgentGate:mean:AV"
    assert by_class["AV"]["kya_reason"] == "ok"
    assert by_class["FSP"]["kya_reason"] == "bad_signature"
    assert by_class["FHJ"]["kya_reason"] == "revoked"


def test_per_seed_rows_and_seed_filter():
    rows = [
        _row("Legacy", "AV", 0.94, score_key="decline", seed=0),
        _row("Legacy", "FH", 0.71, score_key="decline", seed=0),
        _row("Legacy", "AV", 0.95, score_key="decline", seed=1),
        _row("Legacy", "FH", 0.72, score_key="decline", seed=1),
    ]
    all_records, counts = records_from_agentrisk(rows, "Legacy")
    assert counts["n_records"] == 4
    seed0_records, counts0 = records_from_agentrisk(rows, "Legacy", seed=0)
    assert counts0["n_records"] == 2
    assert {r["credential_id"] for r in seed0_records} == {
        "agentrisk:Legacy:seed-0:AV",
        "agentrisk:Legacy:seed-0:FH",
    }
    assert all_records[0]["model_score"] == pytest.approx(0.94)


def test_seed_filter_without_seed_column_raises():
    rows = load_agentrisk_csv(bundled_results_path())
    with pytest.raises(ValueError, match="no seed"):
        records_from_agentrisk(rows, "Legacy", seed=0)


def test_unknown_class_raises():
    with pytest.raises(ValueError, match="unknown agentrisk session class"):
        records_from_agentrisk([_row("Legacy", "XX", 50.0)], "Legacy")


def test_unknown_policy_raises_and_names_policies_seen():
    rows = load_agentrisk_csv(bundled_results_path())
    with pytest.raises(ValueError, match="AgentGate"):
        records_from_agentrisk(rows, "Nope")


def test_empty_rows_raise():
    with pytest.raises(ValueError, match="no agentrisk rows"):
        records_from_agentrisk([], "Legacy")


def test_rows_must_be_a_list():
    with pytest.raises(ValueError, match="list of row dicts"):
        records_from_agentrisk("not rows", "Legacy")


def test_bad_scores_raise():
    cases = [
        _row("Legacy", "AV", 150.0),
        _row("Legacy", "AV", -1.0),
        _row("Legacy", "AV", "high"),
        _row("Legacy", "AV", 1.5, score_key="decline"),
        _row("Legacy", "AV", -0.1, score_key="decline"),
    ]
    for bad in cases:
        with pytest.raises(ValueError):
            records_from_agentrisk([bad], "Legacy")


def test_missing_class_or_score_raises():
    with pytest.raises(ValueError, match="session class"):
        records_from_agentrisk([{"policy": "Legacy", "mean_decline_pct": 50.0}], "Legacy")
    with pytest.raises(ValueError, match="decline rate"):
        records_from_agentrisk([{"policy": "Legacy", "class": "AV"}], "Legacy")


def test_forced_score_column_missing_raises():
    rows = load_agentrisk_csv(bundled_results_path())
    with pytest.raises(ValueError, match="decline"):
        records_from_agentrisk(rows, "Legacy", score_column="decline")
    with pytest.raises(ValueError, match="score_column"):
        records_from_agentrisk(rows, "Legacy", score_column="bogus")


def test_is_legitimate_mismatch_raises():
    row = _row("Legacy", "AV", 94.6, legitimate="fraud")
    with pytest.raises(ValueError, match="disagrees with itself"):
        records_from_agentrisk([row], "Legacy")


def test_is_legitimate_bad_value_raises():
    row = _row("Legacy", "AV", 94.6, legitimate="maybe")
    with pytest.raises(ValueError, match="is_legitimate"):
        records_from_agentrisk([row], "Legacy")


def test_is_legitimate_agreeing_passes():
    rows = [
        _row("Legacy", "AV", 94.6, legitimate="legitimate"),
        _row("Legacy", "FH", 71.4, legitimate="fraud"),
    ]
    records, _ = records_from_agentrisk(rows, "Legacy")
    assert len(records) == 2


def test_threshold_changes_the_confusion_matrix():
    rows = load_agentrisk_csv(bundled_results_path())
    _r, _c, result = score_agentrisk_policy(rows, "Legacy", threshold=0.9)
    # At 0.9 only FH (0.714) among fraud falls below the line.
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (5, 2, 1, 1)
    assert result["precision"] == pytest.approx(5 / 7)


def test_load_rejects_header_only_csv(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("policy,class,mean_decline_pct\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no data rows"):
        load_agentrisk_csv(path)


def test_load_rejects_empty_file(tmp_path):
    path = tmp_path / "blank.csv"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="no header row"):
        load_agentrisk_csv(path)


def test_cls_column_spelling_accepted():
    rows = [
        {"policy": "Legacy", "cls": "AV", "decline": 0.946},
        {"policy": "Legacy", "cls": "FH", "decline": 0.714},
    ]
    records, _ = records_from_agentrisk(rows, "Legacy")
    assert [r["agent_id"] for r in records] == ["AV", "FH"]
