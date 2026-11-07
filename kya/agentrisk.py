"""AgentRisk link-up: score a policy on AgentRisk results with the benchmark hook.

The benchmark hook in ``kya.benchmark`` scores a fraud model on
per-transaction records, and the AgentRisk results dataset
(RishabhPande/agentrisk on Hugging Face) is the first real traffic
to feed it. The dataset is a results file, not a session file: each
row is one (policy, session class) cell with the policy's mean
decline rate for that class across 5 seeds. This module converts
those cells into benchmark records:

- The record's model score is the policy's decline rate for the
  cell: how strongly the policy flags traffic of that class. A row
  from the published file carries ``mean_decline_pct`` (0-100); a
  per-seed row from ``results/main.csv`` in the AgentRisk repo
  carries ``decline`` (0-1). Both are accepted.
- The record's label is the class ground truth: H, AU, and AV are
  legitimate (label 0); FH, FB, FAU, FAV, FHJ, and FSP are fraud
  (label 1). When a row also carries ``is_legitimate``, it must
  agree with the class code, or the row is rejected.

One honest caveat: a cell is an aggregate, not a transaction. The
numbers this produces measure how well a policy's decline behavior
separates fraud classes from legitimate classes at the class level,
not per-transaction discrimination. That is exactly the comparison
the AgentRisk paper makes (Legacy false-declines legitimate
verified agents at 94.6 percent; AgentGate at 1.7 percent), so the
benchmark reproduces the paper's headline as precision, recall,
and AUC instead of restating it. Do not present these numbers as
per-transaction model scores.

Each fraud class maps to the KYA reason that best describes how a
KYA check would fail it. The mapping is a labeling convention so
``score_model`` can score the policy, not a claim that KYA would
emit exactly that reason for the class:

- H (legitimate human): ``ok``. Human traffic carries no agent
  credential, so a KYA check has nothing to fail.
- AU (legitimate unverified agent): ``ok``. The agent is
  legitimate and holds a valid credential; "unverified" describes
  the platform's identity check, not the credential.
- AV (legitimate verified agent): ``ok``.
- FH (manual fraud): ``malformed``. A human fraudster presents no
  agent credential, so a KYA check on the transaction fails as
  malformed.
- FB (scripted bot fraud): ``malformed``. Same: no valid
  credential is presented.
- FAU (fraud via an unverified agent): ``bad_signature``. The
  agent's credential cannot be verified against a trusted issuer.
- FAV (laundering through a permissive agent platform):
  ``bad_scope``. The platform issued an over-broad credential; the
  scope check is the control that should catch it.
- FHJ (hijacked agent): ``revoked``. The agent's credential is
  compromised, and revocation is the KYA response to a compromise.
- FSP (spoofed agent signature): ``bad_signature``. The signature
  does not verify.

Records are traceable to their source cell: ``credential_id`` is
``agentrisk:<policy>:<seed-or-mean>:<class>`` and ``agent_id`` is
the class code. ``load_agentrisk_csv`` reads either the published
means file or a per-seed file; ``bundled_results_path`` points at
the snapshot of the published file shipped with this package
(``kya/agentrisk_results.csv``, copied from the dataset on
2026-11-07), so the demo and tests run offline. For fresh numbers,
download ``data/results.csv`` from the dataset and load that file
instead.

Validation is strict and raises ``ValueError`` on malformed input,
matching the rest of the toolkit: an unknown session class, a
policy that matches no rows, a decline rate outside its range, a
non-numeric score, an ``is_legitimate`` value that disagrees with
the class code, or a seed filter on rows that carry no seed.
"""

import csv
import math
from pathlib import Path

from .benchmark import make_record, score_model
from .credentials import (
    REASON_BAD_SCOPE,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_OK,
    REASON_REVOKED,
)

AGENTRISK_DATASET_URL = "https://huggingface.co/datasets/RishabhPande/agentrisk"
AGENTRISK_RESULTS_URL = AGENTRISK_DATASET_URL + "/resolve/main/data/results.csv"

# Session class -> (KYA reason, label). See the module docstring for
# the rationale behind each fraud mapping.
CLASS_LABELS = {
    "H": (REASON_OK, 0),
    "AU": (REASON_OK, 0),
    "AV": (REASON_OK, 0),
    "FH": (REASON_MALFORMED, 1),
    "FB": (REASON_MALFORMED, 1),
    "FAU": (REASON_BAD_SIGNATURE, 1),
    "FAV": (REASON_BAD_SCOPE, 1),
    "FHJ": (REASON_REVOKED, 1),
    "FSP": (REASON_BAD_SIGNATURE, 1),
}

LEGITIMATE_CLASSES = frozenset({"H", "AU", "AV"})
FRAUD_CLASSES = frozenset({"FH", "FB", "FAU", "FAV", "FHJ", "FSP"})

# Score columns, in the order they are tried: a fraction first
# (per-seed rows), then a percent (published means rows).
_SCORE_COLUMNS = ("decline", "mean_decline_pct")
_CLASS_COLUMNS = ("cls", "class")


def bundled_results_path():
    """Path to the AgentRisk results snapshot shipped with this package."""
    return Path(__file__).with_name("agentrisk_results.csv")


def load_agentrisk_csv(path):
    """Load AgentRisk result rows from a CSV file.

    Returns a list of dicts, one per row, with whitespace stripped
    from keys and string values. Raises ``ValueError`` when the file
    has no header row or no data rows.
    """
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("agentrisk csv has no header row: %s" % path)
        rows = []
        for raw in reader:
            row = {}
            for key, value in raw.items():
                if key is None:
                    continue
                clean_key = key.strip()
                row[clean_key] = value.strip() if isinstance(value, str) else value
            rows.append(row)
    if not rows:
        raise ValueError("agentrisk csv has no data rows: %s" % path)
    return rows


def _clean_row(row):
    """Return a row dict with stripped keys and string values."""
    if not isinstance(row, dict):
        raise ValueError("agentrisk row must be a dict")
    cleaned = {}
    for key, value in row.items():
        if key is None:
            continue
        clean_key = key.strip() if isinstance(key, str) else key
        cleaned[clean_key] = value.strip() if isinstance(value, str) else value
    return cleaned


def _row_value(row, columns, what):
    """Return the first present, non-empty value among ``columns``."""
    for column in columns:
        value = row.get(column)
        if value is not None and value != "":
            return value, column
    raise ValueError("agentrisk row is missing %s" % what)


def _parse_score(value, column):
    """Parse a decline rate into a fraction in [0, 1].

    A ``decline`` value is already a fraction; a
    ``mean_decline_pct`` value is a percent and is divided by 100.
    Raises ``ValueError`` on a non-numeric, non-finite, or
    out-of-range value.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(
            "agentrisk %s is not a number: %r" % (column, value)
        ) from None
    if not math.isfinite(number):
        raise ValueError("agentrisk %s is not finite: %r" % (column, value))
    if column == "mean_decline_pct":
        if number < 0.0 or number > 100.0:
            raise ValueError(
                "agentrisk mean_decline_pct out of range [0, 100]: %r" % value
            )
        return number / 100.0
    if number < 0.0 or number > 1.0:
        raise ValueError("agentrisk decline out of range [0, 1]: %r" % value)
    return number


def _check_is_legitimate(row, cls):
    """Cross-check a row's is_legitimate flag against its class code."""
    flag = row.get("is_legitimate")
    if flag is None or flag == "":
        return
    if flag not in ("legitimate", "fraud"):
        raise ValueError("agentrisk is_legitimate must be legitimate or fraud: %r" % flag)
    expected = "legitimate" if cls in LEGITIMATE_CLASSES else "fraud"
    if flag != expected:
        raise ValueError(
            "agentrisk row disagrees with itself: class %s is %s but "
            "is_legitimate says %s" % (cls, expected, flag)
        )


def records_from_agentrisk(rows, policy, *, seed=None, score_column=None):
    """Build benchmark records for one policy from AgentRisk rows.

    Args:
        rows: result rows as loaded by ``load_agentrisk_csv`` (or
            built by hand as dicts). Each row needs ``policy``, a
            session class under ``cls`` or ``class``, and a decline
            rate under ``decline`` or ``mean_decline_pct``.
        policy: the policy to score, e.g. ``"Legacy"`` or
            ``"AgentGate"``. Matching is exact after stripping
            whitespace.
        seed: when given, only rows with this seed are used. Rows
            without a ``seed`` column cannot be seed-filtered and
            raise ``ValueError``.
        score_column: force one score column (``"decline"`` or
            ``"mean_decline_pct"``). When omitted, ``decline`` is
            tried first, then ``mean_decline_pct``.

    Returns ``(records, counts)`` where ``records`` is a list of
    record dicts as built by ``make_record`` and ``counts`` reports
    ``n_rows`` (rows seen), ``n_policy_rows`` (rows for this policy),
    and ``n_records`` (records built). Raises ``ValueError`` when no
    rows match the policy, so a typo'd policy name can never
    silently score nothing.
    """
    if not isinstance(rows, (list, tuple)):
        raise ValueError("rows must be a list of row dicts")
    if not isinstance(policy, str) or not policy.strip():
        raise ValueError("policy must be a non-empty string")
    if score_column is not None and score_column not in _SCORE_COLUMNS:
        raise ValueError("score_column must be decline or mean_decline_pct")
    policy = policy.strip()

    policies_seen = set()
    matched = []
    for raw_row in rows:
        row = _clean_row(raw_row)
        row_policy = row.get("policy")
        if row_policy is not None and row_policy != "":
            policies_seen.add(row_policy)
        if row_policy != policy:
            continue
        if seed is not None:
            if "seed" not in row or row["seed"] == "":
                raise ValueError(
                    "agentrisk rows carry no seed, cannot filter seed %r" % seed
                )
            if str(row["seed"]) != str(seed):
                continue
        matched.append(row)

    if not matched:
        raise ValueError(
            "no agentrisk rows for policy %r (policies seen: %s)"
            % (policy, sorted(policies_seen) or "none")
        )

    records = []
    for row in matched:
        cls, _ = _row_value(row, _CLASS_COLUMNS, "a session class (cls or class)")
        if cls not in CLASS_LABELS:
            raise ValueError("unknown agentrisk session class: %r" % cls)
        reason, _label = CLASS_LABELS[cls]
        _check_is_legitimate(row, cls)
        if score_column is not None:
            value = row.get(score_column)
            if value is None or value == "":
                raise ValueError(
                    "agentrisk row is missing score column %r" % score_column
                )
            column = score_column
        else:
            value, column = _row_value(row, _SCORE_COLUMNS, "a decline rate")
        score = _parse_score(value, column)
        seed_part = "seed-%s" % row["seed"] if "seed" in row and row["seed"] != "" else "mean"
        records.append(
            make_record(
                score,
                reason,
                credential_id="agentrisk:%s:%s:%s" % (policy, seed_part, cls),
                agent_id=cls,
            )
        )

    counts = {
        "policy": policy,
        "n_rows": len(rows),
        "n_policy_rows": len(matched),
        "n_records": len(records),
    }
    return records, counts


def score_agentrisk_policy(rows, policy, *, threshold=0.5, seed=None, score_column=None):
    """Score one policy on AgentRisk rows, in a single call.

    Builds the policy's records with ``records_from_agentrisk``
    and scores them with ``score_model``. Returns
    ``(records, counts, result)``.
    """
    records, counts = records_from_agentrisk(
        rows, policy, seed=seed, score_column=score_column
    )
    result = score_model(records, threshold=threshold)
    return records, counts, result
