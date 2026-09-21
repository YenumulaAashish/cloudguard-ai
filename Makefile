.PHONY: init fmt validate lint security policy-test test plan clean
init:
	terraform -chdir=terraform init -backend=false -input=false -lockfile=readonly
fmt:
	terraform fmt -recursive terraform
validate:
	bash scripts/validate.sh
lint:
	bash scripts/lint.sh
security:
	bash scripts/security-scan.sh
policy-test:
	bash scripts/policy-test.sh
test:
	python3 scripts/run-offline.py
plan:
	bash scripts/plan-json.sh
clean:
	python3 scripts/clean.py

.PHONY: check-exceptions ci-safety aws-plan plan-json plan-policy evidence
check-exceptions:
	python3 scripts/verify-checkov-exceptions.py
ci-safety:
	python3 scripts/verify-no-deployment-ci.py
aws-plan:
	python3 scripts/aws-plan.py
plan-json: aws-plan
plan-policy:
	python3 scripts/plan-policy.py
evidence:
	python3 scripts/generate-evidence.py
