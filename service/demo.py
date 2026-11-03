"""Run the Know Your Agent demo service locally.

Run from the repo root::

    python -m service.demo

The demo generates a fresh issuer keypair in memory, builds the service
with an empty revocation list and an audit log, issues one sample
credential (agent-shopper-01, up to $50 in electronics, 1 hour), and
prints the issuer public key, the sample credential, and curl examples
for trying the endpoints. Then it serves on http://127.0.0.1:8000.

Everything here is in memory and discarded on exit. The printed
credential is valid for about an hour from startup, and only against
this running demo, because only this demo holds the matching issuer
key. Never reuse demo keys or demo credentials for real authorization.
"""

import json
from datetime import datetime, timedelta, timezone

from kya import (
    AuditLog,
    RevocationList,
    generate_keypair,
    issue_credential,
    public_key_to_pem,
)

from service.app import create_app


def build_demo():
    """Build the demo app and its sample credential. Returns (app, data).

    ``data`` carries the issuer public key PEM and the sample
    credential dict, so a caller that embeds the demo (tests, a
    notebook) can use them without parsing stdout.
    """
    private_key, public_key = generate_keypair()
    revocations = RevocationList()
    audit = AuditLog(private_key)
    app = create_app(public_key, revocations=revocations, audit=audit)

    now = datetime.now(timezone.utc)
    credential = issue_credential(
        private_key,
        agent_id="agent-shopper-01",
        principal="user-123",
        scope={"max_amount_usd": 50.0, "categories": ["electronics"]},
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    audit.record_issued(credential)
    return app, {
        "public_key_pem": public_key_to_pem(public_key),
        "credential": credential,
    }


def main():
    import uvicorn

    app, data = build_demo()
    print("Know Your Agent demo service on http://127.0.0.1:8000")
    print()
    print("Issuer public key (PEM):")
    print(data["public_key_pem"])
    print("Sample credential (save this JSON, it is valid for ~1 hour):")
    print(json.dumps(data["credential"], indent=2))
    print()
    print("Try it (replace CREDENTIAL_JSON with the JSON above):")
    print("  curl -X POST http://127.0.0.1:8000/verify \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"credential\": CREDENTIAL_JSON}'")
    print("  curl -X POST http://127.0.0.1:8000/checkout \\")
    print("    -H 'Content-Type: application/json' \\")
    print(
        "    -d '{\"credential\": CREDENTIAL_JSON, "
        "\"amount_usd\": 30.0, \"category\": \"electronics\"}'"
    )
    print("  curl http://127.0.0.1:8000/audit")
    print()
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
