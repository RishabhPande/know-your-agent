"""Purchase authorization against a verified agent credential (v0.1).

This module answers the merchant-side question: given a credential that has
already passed signature and session checks, is this specific purchase inside
its scope? It does not issue or verify credentials itself; see credentials.py.
"""

import math

from .credentials import verify_credential

REASON_ALLOWED = "allowed"
REASON_AMOUNT_EXCEEDS_SCOPE = "amount_exceeds_scope"
REASON_CATEGORY_NOT_ALLOWED = "category_not_allowed"
REASON_NO_PURCHASE_SCOPE = "no_purchase_scope"
REASON_INVALID_AMOUNT = "invalid_amount"


def check_purchase(payload, amount_usd, category):
    """Check a purchase against a credential payload's scope.

    Args:
        payload: the "payload" dict of a verified credential.
        amount_usd: purchase amount as a number.
        category: purchase category as a string.

    Returns:
        (True, "allowed") or (False, reason).
    """
    if not isinstance(amount_usd, (int, float)) or isinstance(amount_usd, bool):
        return False, REASON_INVALID_AMOUNT
    if not math.isfinite(amount_usd) or amount_usd <= 0:
        return False, REASON_INVALID_AMOUNT
    if not isinstance(category, str) or not category:
        return False, REASON_CATEGORY_NOT_ALLOWED
    scope = payload.get("scope") if isinstance(payload, dict) else None
    if not isinstance(scope, dict):
        return False, REASON_NO_PURCHASE_SCOPE
    max_amount = scope.get("max_amount_usd")
    categories = scope.get("categories")
    if max_amount is None and categories is None:
        return False, REASON_NO_PURCHASE_SCOPE
    if max_amount is not None and amount_usd > max_amount:
        return False, REASON_AMOUNT_EXCEEDS_SCOPE
    if categories is not None and category not in categories:
        return False, REASON_CATEGORY_NOT_ALLOWED
    return True, REASON_ALLOWED


def authorize_purchase(public_key, credential, amount_usd, category, **verify_kwargs):
    """Verify a credential and check a purchase against it, in one call.

    Returns (True, "allowed") only when verification passes AND the purchase
    is inside scope. Otherwise returns (False, reason) where reason is the
    verification reason (e.g. "bad_signature", "expired", "revoked") or the
    scope reason (e.g. "amount_exceeds_scope", "category_not_allowed").
    """
    ok, reason = verify_credential(public_key, credential, **verify_kwargs)
    if not ok:
        return False, reason
    return check_purchase(credential["payload"], amount_usd, category)
