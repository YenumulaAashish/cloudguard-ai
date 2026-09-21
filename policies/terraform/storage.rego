package main

import rego.v1

bucket_control(bucket, kind) := {control |
	some control in resources
	control.type == kind
	is_string(bucket.values.bucket)
	bucket.values.bucket != ""
	control.values.bucket == bucket.values.bucket
}

protected(bucket) if {
	some c in bucket_control(bucket, "aws_s3_bucket_public_access_block")
	c.values.block_public_acls == true
	c.values.block_public_policy == true
	c.values.ignore_public_acls == true
	c.values.restrict_public_buckets == true
}

encrypted(bucket) if {
	some c in bucket_control(bucket, "aws_s3_bucket_server_side_encryption_configuration")
	some rule in c.values.rule
	some encryption in rule.apply_server_side_encryption_by_default
	encryption.sse_algorithm in {"AES256", "aws:kms", "aws:kms:dsse"}
}

deny contains sprintf("S3_PUBLIC: %s requires all four public access blocks", [b.address]) if {
	some b in resources
	b.type == "aws_s3_bucket"
	not protected(b)
}

deny contains sprintf("S3_ENCRYPTION: %s requires explicit known encryption", [b.address]) if {
	some b in resources
	b.type == "aws_s3_bucket"
	not encrypted(b)
}

deny contains sprintf("S3_PUBLIC: %s enables a public ACL", [r.address]) if {
	some r in resources
	r.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
	object.get(r.values, "acl", "private") in {"public-read", "public-read-write", "authenticated-read"}
}
