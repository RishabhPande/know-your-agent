"""Tests for per-seed AgentRisk scoring with confidence intervals."""

import json
import math

import pytest

from kya.agentrisk import (
    bundled_per_seed_results_path,
    bundled_results_path,
    load_agentrisk_csv,
    score_agentrisk_policy,
    score_agentrisk_policy_per_seed,
    summarize_values,
)

ALL_CLASSES = ("H", "AU", "AV", "FH", "FB", "FAU", "FAV", "FHJ", "FSP")


def _row(policy, cls, decline, seed):
    return {"policy": policy, "class": cls, "decline": decline, "seed": seed}


def _seed_rows(seed, *, av_decline=0.94, fh_decline=0.71):
    """One seed of Legacy-like rows; AV and FH declines vary by test."""
    declines = {
        "H": 0.02,
        "AU": 0.94,
        "AV": av_decline,
        "FH": fh_decline,
        "FB": 0.99,
        "FAU": 0.99,
        "FAV": 0.98,
        "FHJ": 0.96,
        "FSP": 0.98,
    }
    return [_row("Legacy", cls, declines[cls], seed) for cls in ALL_CLASSES]


def test_bundled_per_seed_snapshot_loads_495_rows():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    assert len(rows) == 495
    assert sorted({row["seed"] for row in rows}) == ["0", "1", "2", "3", "4"]
    assert len({row["policy"] for row in rows}) == 11
    assert sorted({row["cls"] for row in rows}) == sorted(ALL_CLASSES)


def test_per_seed_legacy_is_seed_stable():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    assert summary["policy"] == "Legacy"
    assert summary["n_seeds"] == 5
    assert summary["seeds"] == [0, 1, 2, 3, 4]
    assert summary["confidence"] == 0.95
    for entry in per_seed:
        assert entry["n_records"] == 9
        assert entry["precision"] == pytest.approx(0.75)
        assert entry["recall"] == pytest.approx(1.0)
        assert entry["auc"] == pytest.approx(16 / 18)
    auc = summary["metrics"]["auc"]
    assert auc["n"] == 5
    assert auc["mean"] == pytest.approx(16 / 18)
    assert auc["std"] == pytest.approx(0.0)
    assert auc["ci_half_width"] == pytest.approx(0.0)
    assert auc["ci_low"] == pytest.approx(16 / 18)
    assert auc["ci_high"] == pytest.approx(16 / 18)


def test_per_seed_agentgate_is_perfect_on_every_seed():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "AgentGate")
    for entry in per_seed:
        assert entry["precision"] == pytest.approx(1.0)
        assert entry["recall"] == pytest.approx(1.0)
        assert entry["auc"] == pytest.approx(1.0)
    for metric in ("precision", "recall", "f1", "accuracy", "auc"):
        assert summary["metrics"][metric]["mean"] == pytest.approx(1.0)
        assert summary["metrics"][metric]["ci_half_width"] == pytest.approx(0.0)


def test_per_seed_entry_matches_single_seed_score():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    per_seed, _summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    _records, _counts, single = score_agentrisk_policy(rows, "Legacy", seed=2)
    entry = per_seed[2]
    assert entry["seed"] == 2
    assert entry["tp"] == single["tp"]
    assert entry["fp"] == single["fp"]
    assert entry["precision"] == pytest.approx(single["precision"])
    assert entry["auc"] == pytest.approx(single["auc"])


def test_per_seed_summary_with_varying_seeds():
    rows = (
        _seed_rows(0)
        + _seed_rows(1, av_decline=0.40)
        + _seed_rows(2, fh_decline=0.40)
    )
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    assert [entry["seed"] for entry in per_seed] == [0, 1, 2]
    assert per_seed[0]["precision"] == pytest.approx(0.75)
    assert per_seed[1]["precision"] == pytest.approx(6 / 7)
    assert per_seed[1]["auc"] == pytest.approx(17 / 18)
    assert per_seed[2]["recall"] == pytest.approx(5 / 6)
    precision = summary["metrics"]["precision"]
    assert precision["n"] == 3
    assert precision["mean"] == pytest.approx(0.7738, abs=1e-4)
    assert precision["std"] == pytest.approx(0.0743, abs=1e-4)
    assert precision["ci_half_width"] == pytest.approx(0.1847, abs=1e-4)
    assert precision["ci_low"] == pytest.approx(0.5891, abs=1e-4)
    assert precision["ci_high"] == pytest.approx(0.9585, abs=1e-4)
    # The 95 percent interval covers every seed's value.
    values = [entry["precision"] for entry in per_seed]
    assert precision["ci_low"] <= min(values)
    assert precision["ci_high"] >= max(values)


def test_per_seed_metric_undefined_on_one_seed_is_excluded():
    flat = [_row("Legacy", cls, 0.0, 0) for cls in ALL_CLASSES]
    rows = flat + _seed_rows(1)
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    assert per_seed[0]["precision"] is None
    assert per_seed[0]["recall"] == pytest.approx(0.0)
    assert per_seed[1]["precision"] == pytest.approx(0.75)
    precision = summary["metrics"]["precision"]
    assert precision["n"] == 1
    assert precision["mean"] == pytest.approx(0.75)
    assert precision["std"] is None
    assert precision["ci_low"] is None
    assert precision["ci_high"] is None
    recall = summary["metrics"]["recall"]
    assert recall["n"] == 2
    assert recall["mean"] == pytest.approx(0.5)


def test_per_seed_metric_undefined_on_all_seeds_is_none():
    rows = []
    for seed in (0, 1):
        for cls in ("H", "AU", "AV"):
            rows.append(_row("Legacy", cls, 0.94, seed))
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    assert all(entry["recall"] is None for entry in per_seed)
    assert all(entry["auc"] is None for entry in per_seed)
    assert summary["metrics"]["recall"] is None
    assert summary["metrics"]["auc"] is None
    assert summary["metrics"]["precision"]["mean"] == pytest.approx(0.0)


def test_per_seed_requires_seed_column():
    rows = load_agentrisk_csv(bundled_results_path())
    with pytest.raises(ValueError, match="no seed"):
        score_agentrisk_policy_per_seed(rows, "Legacy")


def test_per_seed_unknown_policy_raises():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    with pytest.raises(ValueError, match="no agentrisk rows"):
        score_agentrisk_policy_per_seed(rows, "NoSuchPolicy")


def test_per_seed_seeds_sort_numerically():
    rows = _seed_rows("10") + _seed_rows("2")
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "Legacy")
    assert [entry["seed"] for entry in per_seed] == [2, 10]
    assert summary["seeds"] == [2, 10]


def test_per_seed_result_is_json_serializable():
    rows = load_agentrisk_csv(bundled_per_seed_results_path())
    per_seed, summary = score_agentrisk_policy_per_seed(rows, "AgentGate")
    text = json.dumps({"per_seed": per_seed, "summary": summary})
    loaded = json.loads(text)
    assert loaded["summary"]["metrics"]["auc"]["mean"] == pytest.approx(1.0)


def test_summarize_values_known_numbers():
    summary = summarize_values([1, 2, 3, 4, 5])
    assert summary["n"] == 5
    assert summary["mean"] == pytest.approx(3.0)
    assert summary["std"] == pytest.approx(math.sqrt(2.5))
    assert summary["standard_error"] == pytest.approx(math.sqrt(2.5) / math.sqrt(5))
    # df 4, 95 percent t is 2.776.
    assert summary["ci_half_width"] == pytest.approx(
        2.776 * math.sqrt(2.5) / math.sqrt(5)
    )
    assert summary["ci_low"] == pytest.approx(3.0 - summary["ci_half_width"])
    assert summary["ci_high"] == pytest.approx(3.0 + summary["ci_half_width"])


def test_summarize_values_single_value_has_no_interval():
    summary = summarize_values([0.75])
    assert summary["mean"] == pytest.approx(0.75)
    assert summary["std"] is None
    assert summary["standard_error"] is None
    assert summary["ci_low"] is None
    assert summary["ci_high"] is None
    assert summary["ci_half_width"] is None


def test_summarize_values_rejects_bad_input():
    with pytest.raises(ValueError, match="non-empty"):
        summarize_values([])
    with pytest.raises(ValueError, match="finite"):
        summarize_values([0.5, float("nan")])
    with pytest.raises(ValueError, match="finite"):
        summarize_values([0.5, "0.6"])
    with pytest.raises(ValueError, match="confidence"):
        summarize_values([1, 2, 3], confidence=0.80)


def test_higher_confidence_is_wider():
    values = [0.70, 0.75, 0.80, 0.85, 0.90]
    narrow = summarize_values(values, confidence=0.95)
    wide = summarize_values(values, confidence=0.99)
    assert wide["ci_half_width"] > narrow["ci_half_width"]
    assert wide["ci_low"] < narrow["ci_low"]
    assert wide["ci_high"] > narrow["ci_high"]


def test_summarize_values_many_points_uses_normal_approximation():
    values = [i / 100.0 for i in range(32)]
    summary = summarize_values(values)
    assert summary["n"] == 32
    assert summary["mean"] == pytest.approx(0.155)
    # df 31 is above the table, so the 1.96 normal value applies.
    assert summary["ci_half_width"] == pytest.approx(
        1.96 * summary["standard_error"]
    )


@pytest.mark.parametrize("score", [0.02, 0.90])
def test_per_seed_rejects_duplicate_cells_instead_of_reweighting(score):
    rows = _seed_rows(0) + _seed_rows(1)
    duplicate = dict(rows[0], decline=score)
    with pytest.raises(ValueError, match="duplicate.*seed.*class"):
        score_agentrisk_policy_per_seed(rows + [duplicate], "Legacy")


def test_per_seed_duplicate_check_respects_aliases_and_whitespace():
    rows = _seed_rows(0)
    duplicate = {"policy": " Legacy ", "cls": " H ",
                 "decline": 0.02, "seed": " 0 "}
    with pytest.raises(ValueError, match="duplicate.*seed.*class"):
        score_agentrisk_policy_per_seed(rows + [duplicate], "Legacy")


def test_per_seed_same_class_in_other_seed_or_policy_is_not_duplicate():
    rows = _seed_rows(0) + _seed_rows(1)
    other_policy = dict(rows[0], policy="Other")
    expected = score_agentrisk_policy_per_seed(rows, "Legacy")
    actual = score_agentrisk_policy_per_seed(rows + [other_policy], "Legacy")
    assert actual == expected
