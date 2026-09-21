"""Run OPA and Conftest tests, preserving all Phase 1 fixture assertions."""
from cloudguard.policy_testing import policy_tests
if __name__ == "__main__":
    raise SystemExit(0 if policy_tests() else 1)
