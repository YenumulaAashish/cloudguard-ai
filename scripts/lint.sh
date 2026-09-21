#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${TFLINT_AWS:-0}" == "1" ]]; then
  tflint --chdir=terraform --recursive --config="$PWD/.tflint.hcl"
else
  echo "NOT RUN â€” optional AWS lint plugin; enable with TFLINT_AWS=1 after tflint --init"
  tflint --chdir=terraform --recursive --config="$PWD/.tflint-core.hcl"
fi
