import { describe, expect, it } from "vitest"
import { evaluateForCloudTrailTampering } from "../../src/detection-rules/evaluationAttacks/cloudTrailTamperingAttack"
import {
	CLOUDTRAIL_LOG_BUCKET_NAME,
	CLOUDTRAIL_TAMPERING_RULE_ID,
	makeCloudTrailEvent,
	makeConfig,
} from "../helpers"

const config = (o = {}) =>
	makeConfig(CLOUDTRAIL_TAMPERING_RULE_ID, {
		category: "Cloud-Infrastructure",
		threshold: 1,
		windowSeconds: 300,
		severity: "critical",
		...o,
	})

const s3Call = (operation: string, bucketName = CLOUDTRAIL_LOG_BUCKET_NAME) =>
	makeCloudTrailEvent({
		operation,
		service: "s3.amazonaws.com",
		bucketName,
	})

describe("evaluateForCloudTrailTampering: CloudTrail calls", () => {
	it.each(["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"])(
		"detects a successful %s",
		(operation) => {
			const result = evaluateForCloudTrailTampering(
				makeCloudTrailEvent({ operation }),
				config(),
			)

			expect(result.detected).toBe(true)
		},
	)

	it("ignores other CloudTrail operations", () => {
		for (const operation of ["LookupEvents", "DescribeTrails", "StartLogging"]) {
			expect(
				evaluateForCloudTrailTampering(
					makeCloudTrailEvent({ operation }),
					config(),
				),
			).toEqual({ detected: false })
		}
	})

	it("ignores a tampering operation name on an unrelated service", () => {
		expect(
			evaluateForCloudTrailTampering(
				makeCloudTrailEvent({
					operation: "StopLogging",
					service: "ec2.amazonaws.com",
				}),
				config(),
			),
		).toEqual({ detected: false })
	})
})

describe("evaluateForCloudTrailTampering: S3 log bucket calls", () => {
	it.each([
		"DeleteBucket",
		"PutBucketPolicy",
		"DeleteBucketPolicy",
		"PutBucketLifecycle",
		"PutBucketLifecycleConfiguration",
	])("detects %s on the CloudTrail log bucket", (operation) => {
		expect(
			evaluateForCloudTrailTampering(s3Call(operation), config()).detected,
		).toBe(true)
	})

	it("ignores the same calls on an unrelated bucket", () => {
		expect(
			evaluateForCloudTrailTampering(
				s3Call("DeleteBucket", "my-app-uploads"),
				config(),
			),
		).toEqual({ detected: false })
	})

	it("ignores S3 calls with no bucket name", () => {
		const event = makeCloudTrailEvent({
			operation: "DeleteBucket",
			service: "s3.amazonaws.com",
		})

		expect(evaluateForCloudTrailTampering(event, config())).toEqual({
			detected: false,
		})
	})

	it("ignores a log-bucket name on a service that is not S3", () => {
		const event = makeCloudTrailEvent({
			operation: "DeleteBucket",
			service: "ec2.amazonaws.com",
			bucketName: CLOUDTRAIL_LOG_BUCKET_NAME,
		})

		expect(evaluateForCloudTrailTampering(event, config())).toEqual({
			detected: false,
		})
	})

	it("ignores non-tampering S3 calls on the log bucket", () => {
		expect(
			evaluateForCloudTrailTampering(s3Call("GetBucketPolicy"), config()),
		).toEqual({ detected: false })
	})
})

describe("evaluateForCloudTrailTampering: status", () => {
	it.each([
		["failed", 2],
		["unknown", 0],
		["other", 99],
	] as const)("ignores a %s call: tampering that did not happen", (_name, status) => {
		expect(
			evaluateForCloudTrailTampering(makeCloudTrailEvent({ status }), config()),
		).toEqual({ detected: false })
	})
})

describe("evaluateForCloudTrailTampering: finding", () => {
	it("returns a complete finding", () => {
		const event = makeCloudTrailEvent({
			actorName: "AccountFullAccessRole",
			ip: "82.77.77.25",
		})

		const result = evaluateForCloudTrailTampering(event, config())

		expect(result.detected).toBe(true)
		if (!result.detected) return

		expect(result.finding).toMatchObject({
			ruleId: CLOUDTRAIL_TAMPERING_RULE_ID,
			severity: "critical",
			actor: "AccountFullAccessRole",
			sourceIp: "82.77.77.25",
			eventId: event.metadata.original_event_uid,
			eventTime: event.time,
			windowSeconds: 0,
			metadata: {},
		})
	})

	it("describes who did what to which resource", () => {
		const result = evaluateForCloudTrailTampering(
			s3Call("DeleteBucket"),
			config(),
		)

		expect(result.detected).toBe(true)
		if (!result.detected) return

		expect(result.finding.description).toContain("AccountFullAccessRole")
		expect(result.finding.description).toContain("DeleteBucket")
		expect(result.finding.description).toContain(CLOUDTRAIL_LOG_BUCKET_NAME)
	})

	it.each(["StopLogging", "DeleteTrail"])(
		"always raises %s as critical, whatever severity is configured",
		(operation) => {
			const result = evaluateForCloudTrailTampering(
				makeCloudTrailEvent({ operation }),
				config({ severity: "low" }),
			)

			expect(result.detected && result.finding.severity).toBe("critical")
		},
	)

	it.each(["UpdateTrail", "PutEventSelectors"])(
		"uses the configured severity for %s",
		(operation) => {
			const result = evaluateForCloudTrailTampering(
				makeCloudTrailEvent({ operation }),
				config({ severity: "medium" }),
			)

			expect(result.detected && result.finding.severity).toBe("medium")
		},
	)

	it("uses the configured severity for tampering with the log bucket", () => {
		const result = evaluateForCloudTrailTampering(
			s3Call("DeleteBucket"),
			config({ severity: "medium" }),
		)

		expect(result.detected && result.finding.severity).toBe("medium")
	})

	it("falls back to the actor uid, then a placeholder, when there is no name", () => {
		const withUid = makeCloudTrailEvent()
		withUid.actor.user.name = undefined

		const withNothing = makeCloudTrailEvent()
		withNothing.actor.user.name = undefined
		withNothing.actor.user.uid = undefined

		const a = evaluateForCloudTrailTampering(withUid, config())
		const b = evaluateForCloudTrailTampering(withNothing, config())

		expect(a.detected && a.finding.actor).toBe("AROAEXAMPLE:session")
		expect(b.detected && b.finding.actor).toBe("unknown actor")
	})

	it("uses a placeholder source IP when the call has none", () => {
		const event = makeCloudTrailEvent()
		event.src_endpoint = { name: "console.amazonaws.com" }

		const result = evaluateForCloudTrailTampering(event, config())

		expect(result.detected && result.finding.sourceIp).toBe("unknown")
	})
})

describe("evaluateForCloudTrailTampering: configuration", () => {
	// The rule is stateless: threshold and window are not used, so whatever is
	// stored for them cannot make it fail.
	it.each([
		{ threshold: undefined, windowSeconds: undefined },
		{ threshold: 0, windowSeconds: 0 },
		{ threshold: 1.5, windowSeconds: 1.5 },
	])("ignores threshold and window (%j)", (override) => {
		const result = evaluateForCloudTrailTampering(
			makeCloudTrailEvent(),
			config(override),
		)

		expect(result.detected).toBe(true)
	})

	it("is pure: it does not touch persistence", () => {
		const result = evaluateForCloudTrailTampering(
			makeCloudTrailEvent(),
			config(),
		)

		expect(result).not.toBeInstanceOf(Promise)
	})
})
