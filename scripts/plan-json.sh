#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Authenticated AWS plan in ap-south-1; no deployment. Raw logs and plans stay private."
python3 scripts/aws-plan.py
