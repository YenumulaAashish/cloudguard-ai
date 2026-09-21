#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
terraform fmt -check -recursive terraform
terraform -chdir=terraform init -backend=false -input=false -lockfile=readonly
terraform -chdir=terraform validate
if command -v tflint >/dev/null 2>&1; then
  bash scripts/lint.sh
else
  echo "NOT RUN — TFLint unavailable (required in CI)"
fi
