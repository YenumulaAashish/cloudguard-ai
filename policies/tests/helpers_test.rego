package main

import rego.v1

fixture_tags := {"Project": "cloudguard-ai", "Environment": "test", "ManagedBy": "Terraform"}

fixture_resource(kind, values) := {"address": sprintf("%s.test", [kind]), "mode": "managed", "type": kind, "values": values}

fixture_plan(resources) := {"planned_values": {"root_module": {"resources": resources}}}

fixture_sg(rule) := fixture_resource("aws_security_group", {"tags": fixture_tags, "ingress": [rule]})

fixture_bucket := fixture_resource("aws_s3_bucket", {"bucket": "fixture-bucket", "tags": fixture_tags})

fixture_block(enabled) := fixture_resource("aws_s3_bucket_public_access_block", {
	"bucket": "fixture-bucket", "block_public_acls": true, "block_public_policy": enabled,
	"ignore_public_acls": true, "restrict_public_buckets": true,
})

fixture_encryption(algorithm) := fixture_resource("aws_s3_bucket_server_side_encryption_configuration", {"bucket": "fixture-bucket", "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": algorithm}]}]})

fixture_iam(effect, action) := fixture_resource("aws_iam_policy", {"tags": fixture_tags, "policy": json.marshal({"Statement": [{"Effect": effect, "Action": action, "Resource": "*"}]})})
