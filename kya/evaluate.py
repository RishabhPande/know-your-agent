"""Gate evaluation: run the KYA gate over a seeded corpus.

The corpus in kya/corpus.py builds labeled traffic, but until now every
consumer that wanted gate results over that traffic wrote its own loop:
walk the transactions, pick authorize_purchase for singles and
authorize_purchase_chain for chains, parse each timestamp, feed the
corpus revocation state back in, then tally the reasons by hand. The
test suite had one such loop, and any report built on the corpus would
have needed another. This module is that loop, written once.

``evaluate_corpus`` runs the real gate, not a reimplementation of it.
Each transaction is judged at its own timestamp, with the corpus
issuer key and the corpus revocation state unless the caller overrides
either one. The result reports, per class and per family:

- how many transactions the gate accepted and rejected,
- how many verdicts were correct, where correct means the gate
  accepted legitimate traffic and rejected everything else (policy
  violations by valid agents and attacks alike),
- the correct rate, and for attack classes the same number under its
  usual name, the catch rate,
- the gate reason for every verdict, tallied per class, so a class
  that fails in a new way shows up as a new reason, not just a lower
  number.

It also names the misses instead of only counting them:
``missed_attack_ids`` lists the attack transactions the gate accepted,
and ``false_reject_ids`` lists the legitimate transactions it turned
away. On the default corpus the missed list is exactly the
in-window replay class, which KYA v0.1 accepts for lack of a nonce.
That limitation is now a line in a result dict that any consumer can
assert on, rather than a fact each consumer has to rediscover.

Validation is strict and raises ``ValueError`` on a malformed corpus,
matching the rest of the toolkit: a corpus that is not a dict, a
transaction with no id, a duplicate transaction id, an unknown kind,
an unparseable timestamp, or a corpus with no issuer key when the
caller does not supply one. A transaction whose credential is itself
malformed is not a validation error here; the gate judges it and
reports its reason, the way it would in production.

The result is a plain JSON-serializable dict. ``evaluation_to_json``
and ``evaluation_from_json`` save and reload one, with the loader
checking the version and the headline counts the way the benchmark
loader does.
"""

import json
from datetime import datetime

from .corpus import ATTACK_CLASSES, LEGIT_CLASSES, POLICY_CLASSES
from .credentials import load_public_key_pem
from .delegation import authorize_purchase_chain
from .policy import authorize_purchase

EVALUATION_VERSION = 1

FAMILY_LEGITIMATE = "legitimate"
FAMILY_POLICY = "policy"
FAMILY_ATTACK = "attack"
FAMILY_UNKNOWN = "unknown"

_CLASS_FAMILIES = {}
for _cls in LEGIT_CLASSES:
    _CLASS_FAMILIES[_cls] = FAMILY_LEGITIMATE
for _cls in POLICY_CLASSES:
    _CLASS_FAMILIES[_cls] = FAMILY_POLICY
for _cls in ATTACK_CLASSES:
    _CLASS_FAMILIES[_cls] = FAMILY_ATTACK


def _family_for(cls, label):
    """Family of a transaction: by class when known, else by label.

    A future corpus class that this module predates is still grouped
    sensibly, from its label: 0 is legitimate, None is a policy
    violation, 1 is an attack. A class with an unusable label lands in
    the unknown family and is never counted correct.
    """
    if cls in _CLASS_FAMILIES:
        return _CLASS_FAMILIES[cls]
    if label == 0:
        return FAMILY_LEGITIMATE
    if label is None:
        return FAMILY_POLICY
    if label == 1:
        return FAMILY_ATTACK
    return FAMILY_UNKNOWN


def _parse_timestamp(value, tx_id):
    if not isinstance(value, str) or not value:
        raise ValueError("transaction %r has no timestamp" % tx_id)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            "transaction %r has an unparseable timestamp: %r" % (tx_id, value)
        ) from exc


def _resolve_public_key(corpus, public_key):
    if public_key is not None:
        return public_key
    pem = corpus.get("issuer_public_key_pem")
    if not isinstance(pem, str) or not pem:
        raise ValueError(
            "corpus carries no issuer_public_key_pem; pass public_key"
        )
    try:
        return load_public_key_pem(pem)
    except Exception as exc:
        raise ValueError("corpus issuer_public_key_pem is not a valid key") from exc


def _resolve_revoked_ids(corpus, revoked_ids):
    if revoked_ids is not None:
        return revoked_ids
    stored = corpus.get("revoked_ids")
    if stored is None:
        return set()
    if not isinstance(stored, (list, tuple, set, frozenset)):
        raise ValueError("corpus revoked_ids must be a list of credential ids")
    return set(stored)


def _empty_bucket():
    return {"n": 0, "accepted": 0, "rejected": 0, "correct": 0}


def _finish_bucket(bucket):
    n = bucket["n"]
    out = dict(bucket)
    out["correct_rate"] = bucket["correct"] / n if n else None
    return out


def evaluate_corpus(corpus, *, public_key=None, revoked_ids=None):
    """Run the KYA gate over every transaction in a built corpus.

    Args:
        corpus: a dict as returned by ``build_corpus`` (or loaded from
            its JSON form, which is the same shape).
        public_key: optional Ed25519 public key object to verify
            against. Defaults to the issuer key the corpus carries at
            ``issuer_public_key_pem``.
        revoked_ids: optional revocation state to judge with, either a
            set of credential ids or a ``RevocationList``. Defaults to
            the corpus ``revoked_ids``. Pass an empty set to measure
            what revocation is worth on this corpus.

    Returns a JSON-serializable dict with the corpus seed, headline
    counts and correct rate, per-family and per-class breakdowns (each
    with accepted, rejected, correct, and correct rate; attack classes
    and the attack family also carry ``catch_rate`` and ``missed``),
    overall reason tallies, the per-transaction verdicts in corpus
    order, and the ``missed_attack_ids`` and ``false_reject_ids``
    lists.
    """
    if not isinstance(corpus, dict):
        raise ValueError("corpus must be a dict from build_corpus")
    transactions = corpus.get("transactions")
    if not isinstance(transactions, list):
        raise ValueError("corpus transactions must be a list")
    key = _resolve_public_key(corpus, public_key)
    revoked = _resolve_revoked_ids(corpus, revoked_ids)

    verdicts = []
    by_class = {}
    by_family = {}
    by_reason = {}
    missed_attack_ids = []
    false_reject_ids = []
    seen_ids = set()
    n_accepted = 0
    n_correct = 0

    for tx in transactions:
        if not isinstance(tx, dict):
            raise ValueError("corpus transaction must be a dict")
        tx_id = tx.get("tx_id")
        if not isinstance(tx_id, str) or not tx_id:
            raise ValueError("corpus transaction has no tx_id")
        if tx_id in seen_ids:
            raise ValueError("duplicate transaction id: %r" % tx_id)
        seen_ids.add(tx_id)
        cls = tx.get("cls")
        if not isinstance(cls, str) or not cls:
            raise ValueError("transaction %r has no class" % tx_id)
        if "label" not in tx or tx["label"] not in (0, 1, None):
            raise ValueError("transaction %r has an invalid label" % tx_id)
        label = tx["label"]
        kind = tx.get("kind")
        now = _parse_timestamp(tx.get("timestamp"), tx_id)
        if kind == "single":
            ok, reason = authorize_purchase(
                key,
                tx.get("credential"),
                tx.get("amount_usd"),
                tx.get("category"),
                now=now,
                revoked_ids=revoked,
            )
        elif kind == "chain":
            ok, reason = authorize_purchase_chain(
                key,
                tx.get("chain"),
                tx.get("amount_usd"),
                tx.get("category"),
                now=now,
                revoked_ids=revoked,
            )
        else:
            raise ValueError(
                "transaction %r has unknown kind: %r" % (tx_id, kind)
            )

        family = _family_for(cls, label)
        # Correct means legitimate traffic gets in and nothing else
        # does. Unknown-family transactions are never counted correct:
        # the evaluator does not know what the gate owed them.
        if family == FAMILY_LEGITIMATE:
            correct = bool(ok)
        elif family in (FAMILY_POLICY, FAMILY_ATTACK):
            correct = not ok
        else:
            correct = False

        verdicts.append(
            {"tx_id": tx_id, "cls": cls, "ok": bool(ok), "reason": reason}
        )
        by_reason[reason] = by_reason.get(reason, 0) + 1
        if ok:
            n_accepted += 1
        if correct:
            n_correct += 1
        if family == FAMILY_ATTACK and ok:
            missed_attack_ids.append(tx_id)
        if family == FAMILY_LEGITIMATE and not ok:
            false_reject_ids.append(tx_id)

        class_bucket = by_class.setdefault(
            cls,
            dict(_empty_bucket(), label=label, family=family, reasons={}),
        )
        family_bucket = by_family.setdefault(family, _empty_bucket())
        for bucket in (class_bucket, family_bucket):
            bucket["n"] += 1
            bucket["accepted" if ok else "rejected"] += 1
            if correct:
                bucket["correct"] += 1
        class_bucket["reasons"][reason] = (
            class_bucket["reasons"].get(reason, 0) + 1
        )

    classes_out = {}
    for cls in sorted(by_class):
        bucket = by_class[cls]
        finished = _finish_bucket(
            {k: bucket[k] for k in ("n", "accepted", "rejected", "correct")}
        )
        finished["label"] = bucket["label"]
        finished["family"] = bucket["family"]
        finished["reasons"] = {
            reason: bucket["reasons"][reason]
            for reason in sorted(bucket["reasons"])
        }
        if bucket["family"] == FAMILY_ATTACK:
            finished["missed"] = bucket["accepted"]
            finished["catch_rate"] = finished["correct_rate"]
        classes_out[cls] = finished

    families_out = {}
    for family in (
        FAMILY_LEGITIMATE,
        FAMILY_POLICY,
        FAMILY_ATTACK,
        FAMILY_UNKNOWN,
    ):
        if family not in by_family:
            continue
        finished = _finish_bucket(by_family[family])
        if family == FAMILY_ATTACK:
            finished["missed"] = finished["accepted"]
            finished["catch_rate"] = finished["correct_rate"]
        families_out[family] = finished

    n = len(transactions)
    return {
        "version": EVALUATION_VERSION,
        "seed": corpus.get("seed"),
        "n_transactions": n,
        "n_accepted": n_accepted,
        "n_rejected": n - n_accepted,
        "n_correct": n_correct,
        "correct_rate": n_correct / n if n else None,
        "by_family": families_out,
        "by_class": classes_out,
        "by_reason": {reason: by_reason[reason] for reason in sorted(by_reason)},
        "missed_attack_ids": missed_attack_ids,
        "false_reject_ids": false_reject_ids,
        "verdicts": verdicts,
    }


def evaluation_to_json(result):
    """Serialize an ``evaluate_corpus`` result to a JSON string."""
    return json.dumps(result, sort_keys=True)


def evaluation_from_json(text):
    """Load an ``evaluate_corpus`` result from JSON, checking its shape."""
    try:
        result = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ValueError("evaluation result is not valid JSON: %s" % exc) from exc
    if not isinstance(result, dict) or result.get("version") != EVALUATION_VERSION:
        raise ValueError("evaluation result has an unsupported version")
    for key in ("n_transactions", "n_accepted", "n_rejected", "n_correct"):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("evaluation result is missing count %r" % key)
    if not isinstance(result.get("by_class"), dict):
        raise ValueError("evaluation result is missing by_class")
    if not isinstance(result.get("verdicts"), list):
        raise ValueError("evaluation result is missing verdicts")
    return result
