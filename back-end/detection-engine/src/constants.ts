export const AUTH_FAILURES_DYNAMO_DB_TABLE =
	process.env.AUTH_FAILURES_DYNAMO_DB_TABLE
export const SECURITY_ALERTS_DYNAMO_DB_TABLE =
	process.env.SECURITY_ALERTS_DYNAMO_DB_TABLE

export const COMPONENT_NAME = "ThreatLensDetectionEngine"

export const EVENT_RETENTION_SECONDS = 3600

export const EVENT_STORED = "STORED"
export const EVENT_DUPLICATE = "DUPLICATE"

export const EVENT_QUARANTINED = "EVENT_QUARANTINED"

export const INVALID_JSON = "INVALID_JSON"
export const INVALID_OCSF_SCHEMA = "OCSF_SCHEMA_VALIDATION_FAILED"

// Calls that stop, remove or reconfigure AWS CloudTrail itself.
export const CLOUD_TAMPERING_OPERATIONS = new Set([
	"StopLogging",
	"DeleteTrail",
	"UpdateTrail",
	"PutEventSelectors",
	"DeleteLogGroup",
])

// Calls that destroy or weaken an S3 bucket holding the CloudTrail logs.
export const S3_BUCKET_TAMPERING_OPERATIONS = new Set([
	"DeleteBucket",
	"PutBucketPolicy",
	"DeleteBucketPolicy",
	"PutBucketLifecycle",
	"PutBucketLifecycleConfiguration",
])

// Default bucket name prefix created by the CloudTrail console.
// First version of "is this the CloudTrail bucket": replace with an explicit
// configured bucket name once that setting exists.
export const CLOUDTRAIL_BUCKET_PREFIX = "aws-cloudtrail-logs-"
export const CLOUDTRAIL_SERVICE = "cloudtrail.amazonaws.com"
export const CLOUDWATCH_SERVICE = "logs.amazonaws.com"
export const S3_SERVICE = "s3.amazonaws.com"
