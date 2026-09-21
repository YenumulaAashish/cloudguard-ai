package main

import rego.v1

test_storage_encrypted if {
	count(deny) == 0 with input as fixture_plan([fixture_bucket, fixture_block(true), fixture_encryption("AES256")])
}

test_storage_missing_encryption if {
	count(deny) == 1 with input as fixture_plan([fixture_bucket, fixture_block(true)])
}

test_storage_kms_boundary if {
	count(deny) == 0 with input as fixture_plan([fixture_bucket, fixture_block(true), fixture_encryption("aws:kms")])
}

test_storage_missing_blocks if {
	count(deny) == 1 with input as fixture_plan([fixture_bucket, fixture_encryption("AES256")])
}

test_storage_other_bucket_control_not_accepted if {
	other := fixture_resource("aws_s3_bucket_server_side_encryption_configuration", {"bucket": "different-bucket", "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})
	count(deny) == 1 with input as fixture_plan([fixture_bucket, fixture_block(true), other])
}
