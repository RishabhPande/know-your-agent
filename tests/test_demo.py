"""End-to-end smoke test for demo.py, the script the README documents.

The README shows the demo's expected output as the repo's quickstart
contract. The unit suite covers the engine and service separately; this
test runs the demo itself so a change that silently breaks the documented
quickstart fails CI.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_LINES = [
    "1. $30 electronics purchase: ACCEPTED (allowed)",
    "2. $500 electronics purchase: REJECTED (amount_exceeds_scope)",
    "3. $30 groceries purchase: REJECTED (category_not_allowed)",
    "4. $30 electronics purchase after revocation: REJECTED (revoked)",
    "5. Tampered credential (agent id changed): REJECTED (bad_signature)",
    "6. Delegated chain (root -> sub-agent, $20): ACCEPTED (ok)",
    "7. $15 electronics purchase via sub-agent: ACCEPTED (allowed)",
    "8. $30 electronics purchase via sub-agent (over leaf limit): REJECTED (amount_exceeds_scope)",
    "9. Audit log (3 entries) verifies: ACCEPTED (ok)",
    "10. Tampered audit entry (outcome rewritten): REJECTED (bad_hash_chain)",
    "11. Benchmark (toy model, 3 scored, 1 ambiguous excluded): precision 1.00, recall 1.00, AUC 1.00",
    "12. AgentRisk Legacy (9 cells): precision 0.75, recall 1.00, AUC 0.89",
    "12. AgentRisk AgentGate (9 cells): precision 1.00, recall 1.00, AUC 1.00",
    "13. AgentRisk Legacy per seed (5 seeds): mean AUC 0.89, 95% CI [0.89, 0.89]",
    "13. AgentRisk AgentGate per seed (5 seeds): mean AUC 1.00, 95% CI [1.00, 1.00]",
    "14. Seeded corpus (seed 20261112, 5100 transactions, 20 classes): 2500 legitimate, 650 policy, 1950 attacks; deterministic rebuild matches: True",
    "15. Gate evaluation (default corpus): legitimate 2500/2500 accepted, policy 650/650 rejected, attacks 1850/1950 caught (100 missed: attack_replay_in_window)",
    "16. Gate evaluation with replay protection: attacks 1950/1950 caught (0 missed)",
    "16. Replay protection (presentation demo-order-1): first spend ACCEPTED (allowed), replay REJECTED (replay)",
    "17. Shared state (two processes, one file): first spend ACCEPTED (allowed), replay in other process REJECTED (replay)",
    "17. Shared state: revocation in one process seen in the other: REJECTED (revoked)",
    "18. Remote state (two machines, one backend): first spend ACCEPTED (allowed), replay on other machine REJECTED (replay)",
    "18. Remote state: revocation on one machine seen on the other: REJECTED (revoked)",
    "19. Authenticated state (correct token): revocation read back: REJECTED (revoked)",
    "19. Authenticated state (no token): REJECTED (unauthenticated)",
]


def run_demo():
    return subprocess.run(
        [sys.executable, "demo.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_demo_exits_cleanly():
    result = run_demo()
    assert result.returncode == 0, (
        f"demo.py exited {result.returncode}\nstderr:\n{result.stderr}"
    )


def test_demo_prints_documented_outcomes():
    result = run_demo()
    missing = [line for line in EXPECTED_LINES if line not in result.stdout]
    assert not missing, (
        "demo.py output no longer matches the README contract; "
        f"missing lines:\n" + "\n".join(missing)
    )
