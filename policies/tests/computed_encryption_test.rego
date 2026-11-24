package main

import rego.v1

computed_encryption_plan(mask, algorithm) := plan_changes([fixture_bucket, fixture_block(true)], [change_fixture(fixture_encryption(algorithm), ["create"], fixture_encryption(algorithm).values, {"rule": mask})])

test_known_aes256_computed_metadata_allowed if {
	mask := [{"bucket_key_enabled": true, "blocked_encryption_types": true, "apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}]
	count(deny) == 0 with input as computed_encryption_plan(mask, "AES256")
}

test_unknown_algorithm_still_blocks if {
	mask := [{"apply_server_side_encryption_by_default": [{"sse_algorithm": true}]}]
	count(deny) > 0 with input as computed_encryption_plan(mask, "AES256")
}

test_unknown_whole_rule_still_blocks if {
	count(deny) > 0 with input as computed_encryption_plan(true, "AES256")
}

test_unknown_kms_key_not_exempted if {
	mask := [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}]
	count(deny) > 0 with input as computed_encryption_plan(mask, "aws:kms")
}

test_unknown_other_rule_field_still_blocks if {
	count(deny) > 0 with input as computed_encryption_plan([{"other": true}], "AES256")
}
