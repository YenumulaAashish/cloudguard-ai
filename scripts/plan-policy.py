"""Evaluate an existing real tfplan.json without making an AWS request."""
from cloudguard.planning import plan_policy
if __name__ == "__main__":
    raise SystemExit(0 if plan_policy() else 1)
