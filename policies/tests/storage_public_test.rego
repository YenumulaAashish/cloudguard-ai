package main

import rego.v1

test_public_s3_rejected if {
	count(deny) == 1 with input as fixture_plan([fixture_bucket, fixture_block(false), fixture_encryption("AES256")])
}

test_invalid_input_rejected if count(deny) == 1 with input as {}

test_nested_module_checked if {
	p := {"planned_values": {"root_module": {"child_modules": [{"resources": [fixture_bucket]}]}}}
	count(deny) == 2 with input as p
}
