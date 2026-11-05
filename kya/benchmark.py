"""Benchmark hook: score a fraud model on agent traffic.

A fraud model needs labeled traffic to be scored against, and Know Your
Agent already produces labels as a side effect of doing its job. Every
verification ends in a verdict with a reason code, and that verdict is a
ground-truth label for the transaction it judged:

- A credential that verifies and a purchase inside its scope is a
  legitimate transaction: label 0.
- A credential rejected for a credential reason (revoked, bad signature,
  expired, not yet valid, bad scope, malformed, or a broken delegation
  chain) is a fraud attempt: label 1. The agent either presented stolen
  or revoked credentials, forged one, or presented one outside its
  session window.

Purchase-policy rejections (amount over the scope limit, a category
outside the scope) are a third case and are labeled ambiguous. The agent
held a valid credential and simply asked for more than it was allowed,
which is a policy violation by a legitimate agent, not evidence of fraud.
Those records are excluded from scoring by default and counted
separately, so they can never inflate or deflate a model's numbers
without the caller noticing.

A record is one scored transaction: the fraud model's score for it
(0.0 means surely legitimate, 1.0 means surely fraud) plus the KYA
reason that labels it. ``score_model`` turns a list of records into
the standard numbers: confusion matrix at a threshold, precision,
recall, F1, accuracy, and AUC. AUC is computed by the rank method in
pure Python (no extra dependency), with ties counted as half a win, so
it matches the usual definition. When the records hold only one class,
AUC is undefined and comes back as ``None`` rather than a made-up
number, and the same holds for precision when the model flags nothing,
recall when there is no fraud to find, and F1 when both are undefined.

Records can be built by hand with ``make_record``, or from an audit
log with ``records_from_audit``: it takes the ``verified`` entries of
an ``AuditLog`` (their outcomes are the KYA reasons) and pairs each
one with the model's score for that credential id, from a dict the
caller supplies. Entries with no model score are excluded and counted,
never silently treated as a zero score.

The result is plain JSON-serializable dicts, so a benchmark run can be
saved next to the audit log it was scored from. The record format is
documented here so other traffic sources can be converted to it; the
AgentRisk cases (RishabhPande/agentrisk on Hugging Face) are the
natural next source, since each case already carries an agent
transaction and an expected verdict.

Validation is strict and raises ``ValueError`` on malformed input,
matching the rest of the toolkit: a model score outside [0, 1], a
non-finite score, an unknown KYA reason, or a record that is not a
dict. Scoring never guesses at a label. An empty record list is a
valid empty benchmark: all counts are zero and every metric is
``None``.
"""

import json
import math

from .audit import KIND_VERIFIED
from .credentials import (
    REASON_BAD_SCOPE,
    REASON_BAD_SIGNATURE,
    REASON_EXPIRED,
    REASON_MALFORMED,
    REASON_NOT_YET_VALID,
    REASON_OK,
    REASON_REVOKED,
    REASON_UNSUPPORTED_ALGORITHM,
)
from .delegation import (
    REASON_BAD_CHAIN,
    REASON_PRINCIPAL_MISMATCH,
    REASON_SCOPE_WIDENED,
    REASON_WINDOW_WIDENED,
)
from .policy import (
    REASON_ALLOWED,
    REASON_AMOUNT_EXCEEDS_SCOPE,
    REASON_CATEGORY_NOT_ALLOWED,
    REASON_INVALID_AMOUNT,
    REASON_NO_PURCHASE_SCOPE,
)

BENCHMARK_VERSION = 1

# KYA reasons that label a transaction legitimate (label 0).
LEGITIMATE_REASONS = frozenset({REASON_OK, REASON_ALLOWED})

# KYA reasons that label a transaction a fraud attempt (label 1).
FRAUD_REASONS = frozenset(
    {
        REASON_REVOKED,
        REASON_BAD_SIGNATURE,
        REASON_EXPIRED,
        REASON_NOT_YET_VALID,
        REASON_BAD_SCOPE,
        REASON_MALFORMED,
        REASON_UNSUPPORTED_ALGORITHM,
        REASON_BAD_CHAIN,
        REASON_PRINCIPAL_MISMATCH,
        REASON_SCOPE_WIDENED,
        REASON_WINDOW_WIDENED,
    }
)

# KYA reasons that are ambiguous as fraud labels: a valid credential
# asking for more than its scope allows. Excluded from scoring.
AMBIGUOUS_REASONS = frozenset(
    {
        REASON_AMOUNT_EXCEEDS_SCOPE,
        REASON_CATEGORY_NOT_ALLOWED,
        REASON_NO_PURCHASE_SCOPE,
        REASON_INVALID_AMOUNT,
    }
)

KNOWN_REASONS = LEGITIMATE_REASONS | FRAUD_REASONS | AMBIGUOUS_REASONS


def label_for_reason(reason):
    """Return the fraud label for a KYA reason, or None when ambiguous.

    Returns 0 for a legitimate verdict, 1 for a fraud verdict, and
    None for a purchase-policy rejection, which is neither. Raises
    ``ValueError`` on an unknown reason, so a typo can never silently
    become a label.
    """
    if not isinstance(reason, str) or not reason:
        raise ValueError("kya reason must be a non-empty string")
    if reason in LEGITIMATE_REASONS:
        return 0
    if reason in FRAUD_REASONS:
        return 1
    if reason in AMBIGUOUS_REASONS:
        return None
    raise ValueError("unknown kya reason: %r" % reason)


def make_record(model_score, kya_reason, *, credential_id=None, agent_id=None):
    """Build one benchmark record, validating the score and the reason.

    ``model_score`` is the fraud model's score for the transaction,
    a finite number in [0, 1]. ``kya_reason`` is the KYA verdict
    reason that labels it. ``credential_id`` and ``agent_id`` are
    optional identifiers kept for tracing a scored transaction back
    to the credential it came from.
    """
    if (
        not isinstance(model_score, (int, float))
        or isinstance(model_score, bool)
        or not math.isfinite(model_score)
        or model_score < 0.0
        or model_score > 1.0
    ):
        raise ValueError("model_score must be a finite number in [0, 1]")
    label_for_reason(kya_reason)
    if credential_id is not None and (
        not isinstance(credential_id, str) or not credential_id
    ):
        raise ValueError("credential_id must be a non-empty string")
    if agent_id is not None and (not isinstance(agent_id, str) or not agent_id):
        raise ValueError("agent_id must be a non-empty string")
    record = {"model_score": float(model_score), "kya_reason": kya_reason}
    if credential_id is not None:
        record["credential_id"] = credential_id
    if agent_id is not None:
        record["agent_id"] = agent_id
    return record


def _validate_record(record):
    """Validate a record dict and return (model_score, label or None)."""
    if not isinstance(record, dict):
        raise ValueError("benchmark record must be a dict")
    if "model_score" not in record or "kya_reason" not in record:
        raise ValueError("benchmark record needs model_score and kya_reason")
    checked = make_record(
        record["model_score"],
        record["kya_reason"],
        credential_id=record.get("credential_id"),
        agent_id=record.get("agent_id"),
    )
    return checked["model_score"], label_for_reason(checked["kya_reason"])


def _auc(scores_labels):
    """Rank-based AUC for (model_score, label) pairs, ties as half wins.

    Returns None when the pairs hold only one class.
    """
    positives = [s for s, label in scores_labels if label == 1]
    negatives = [s for s, label in scores_labels if label == 0]
    if not positives or not negatives:
        return None
    wins = 0.0
    for pos in positives:
        for neg in negatives:
            if pos > neg:
                wins += 1.0
            elif pos == neg:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def score_model(records, *, threshold=0.5):
    """Score a fraud model against KYA-labeled records.

    Args:
        records: a list of record dicts as built by ``make_record``.
            Ambiguous records (purchase-policy rejections) are
            excluded from the metrics and counted separately.
        threshold: a model score at or above this value counts as a
            fraud prediction. Must be a finite number in [0, 1].

    Returns a JSON-serializable dict with the threshold, the counts
    (``n_records``, ``n_scored``, ``n_excluded_ambiguous``), the
    confusion matrix (``tp``, ``fp``, ``tn``, ``fn``), the metrics
    (``precision``, ``recall``, ``f1``, ``accuracy``, ``auc``, each
    ``None`` when undefined for these records), the fraud base rate
    among scored records, and a per-reason breakdown giving, for each
    KYA reason seen, how many records carried it and their mean model
    score.
    """
    if (
        not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or not math.isfinite(threshold)
        or threshold < 0.0
        or threshold > 1.0
    ):
        raise ValueError("threshold must be a finite number in [0, 1]")
    if not isinstance(records, (list, tuple)):
        raise ValueError("records must be a list of record dicts")

    scored = []
    excluded_ambiguous = 0
    by_reason = {}
    for record in records:
        score, label = _validate_record(record)
        reason = record["kya_reason"]
        bucket = by_reason.setdefault(
            reason, {"n": 0, "mean_model_score": 0.0, "_total": 0.0}
        )
        bucket["n"] += 1
        bucket["_total"] += score
        if label is None:
            excluded_ambiguous += 1
            continue
        scored.append((score, label))

    tp = fp = tn = fn = 0
    for score, label in scored:
        predicted_fraud = score >= threshold
        if predicted_fraud and label == 1:
            tp += 1
        elif predicted_fraud and label == 0:
            fp += 1
        elif not predicted_fraud and label == 0:
            tn += 1
        else:
            fn += 1

    n_scored = len(scored)
    n_fraud = tp + fn
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / n_fraud if n_fraud else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    accuracy = (tp + tn) / n_scored if n_scored else None
    auc = _auc(scored)
    base_rate = n_fraud / n_scored if n_scored else None

    breakdown = {}
    for reason in sorted(by_reason):
        bucket = by_reason[reason]
        breakdown[reason] = {
            "n": bucket["n"],
            "mean_model_score": bucket["_total"] / bucket["n"],
        }

    return {
        "version": BENCHMARK_VERSION,
        "threshold": float(threshold),
        "n_records": len(records),
        "n_scored": n_scored,
        "n_excluded_ambiguous": excluded_ambiguous,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "auc": auc,
        "base_rate": base_rate,
        "by_reason": breakdown,
    }


def records_from_audit(entries, model_scores):
    """Build benchmark records from audit log ``verified`` entries.

    Args:
        entries: audit entries as returned by ``AuditLog.entries()``
            (or loaded from JSON). Only entries of kind ``verified``
            are used; other kinds are skipped and counted.
        model_scores: a dict mapping credential id to the fraud
            model's score for that transaction.

    Returns ``(records, counts)`` where ``records`` is a list of
    record dicts and ``counts`` reports ``n_verified`` (verified
    entries seen), ``n_scored`` (records built), ``n_no_model_score``
    (verified entries with no score for their credential id, excluded
    and counted), and ``n_skipped_kinds`` (non-verified entries).
    An audit entry whose outcome is an unknown reason raises
    ``ValueError``, so a corrupt or foreign log cannot silently
    become labels.
    """
    if not isinstance(entries, (list, tuple)):
        raise ValueError("entries must be a list of audit entry dicts")
    if not isinstance(model_scores, dict):
        raise ValueError("model_scores must be a dict of credential id to score")

    records = []
    counts = {
        "n_verified": 0,
        "n_scored": 0,
        "n_no_model_score": 0,
        "n_skipped_kinds": 0,
    }
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kind") != KIND_VERIFIED:
            counts["n_skipped_kinds"] += 1
            continue
        counts["n_verified"] += 1
        credential_id = entry.get("credential_id")
        if not isinstance(credential_id, str) or not credential_id:
            raise ValueError("verified audit entry has no credential_id")
        outcome = entry.get("outcome")
        label_for_reason(outcome)
        if credential_id not in model_scores:
            counts["n_no_model_score"] += 1
            continue
        records.append(
            make_record(
                model_scores[credential_id],
                outcome,
                credential_id=credential_id,
                agent_id=entry.get("agent_id"),
            )
        )
        counts["n_scored"] += 1
    return records, counts


def result_to_json(result):
    """Serialize a ``score_model`` result to a JSON string."""
    return json.dumps(result, sort_keys=True)


def result_from_json(text):
    """Load a ``score_model`` result from JSON, validating its shape."""
    try:
        result = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ValueError("benchmark result is not valid JSON: %s" % exc) from exc
    if not isinstance(result, dict) or result.get("version") != BENCHMARK_VERSION:
        raise ValueError("benchmark result has an unsupported version")
    for key in ("n_records", "n_scored", "tp", "fp", "tn", "fn"):
        if not isinstance(result.get(key), int) or isinstance(result.get(key), bool):
            raise ValueError("benchmark result is missing count %r" % key)
    return result
