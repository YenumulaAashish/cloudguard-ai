package main

import rego.v1

test_iam_scoped_allow if count(deny) == 0 with input as fixture_plan([fixture_iam("Allow", ["s3:GetObject"])])

test_iam_wildcard if count(deny) == 1 with input as fixture_plan([fixture_iam("Allow", "*")])

test_iam_deny_boundary if count(deny) == 0 with input as fixture_plan([fixture_iam("Deny", "*")])

test_iam_service_wildcard if count(deny) == 1 with input as fixture_plan([fixture_iam("Allow", ["s3:*"])])

test_iam_invalid_json if {
	r := fixture_resource("aws_iam_policy", {"tags": fixture_tags, "policy": "not json"})
	count(deny) == 1 with input as fixture_plan([r])
}
