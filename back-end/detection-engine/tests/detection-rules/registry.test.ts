import { describe, expect, it } from "vitest"
import { detectionRuleEvaluationRegistry } from "../../src/detection-rules/evalutationRegistry"
import {
	BRUTE_FORCE_RULE_ID,
	CLOUDTRAIL_TAMPERING_RULE_ID,
	makeCloudTrailEvent,
	makeConfig,
	makeEvent,
	makeFailures,
	PASSWORD_SPRAYING_RULE_ID,
	SUCCESS_AFTER_FAILURES_RULE_ID,
} from "../helpers"

const authenticationRules = detectionRuleEvaluationRegistry.flatMap((rule) =>
	rule.eventType === "authentication" ? [rule] : [],
)

const cloudTrailRules = detectionRuleEvaluationRegistry.flatMap((rule) =>
	rule.eventType === "cloudtrail" ? [rule] : [],
)

const detectedRuleIds = (
	event: ReturnType<typeof makeEvent>,
	recentFailures: ReturnType<typeof makeFailures>,
) =>
	authenticationRules
		.filter(
			(rule) =>
				rule.evaluate({
					event,
					recentFailures,
					configuration: makeConfig(rule.id),
				}).detected,
		)
		.map((rule) => rule.id)

describe("detectionRuleEvaluationRegistry", () => {
	it("registers every rule exactly once, with unique IDs", () => {
		const ids = detectionRuleEvaluationRegistry.map((r) => r.id)

		expect(ids).toEqual([
			BRUTE_FORCE_RULE_ID,
			PASSWORD_SPRAYING_RULE_ID,
			SUCCESS_AFTER_FAILURES_RULE_ID,
			CLOUDTRAIL_TAMPERING_RULE_ID,
		])
		expect(new Set(ids).size).toBe(ids.length)
	})

	it("declares which kind of event each rule evaluates", () => {
		expect(authenticationRules.map((r) => r.id)).toEqual([
			BRUTE_FORCE_RULE_ID,
			PASSWORD_SPRAYING_RULE_ID,
			SUCCESS_AFTER_FAILURES_RULE_ID,
		])
		expect(cloudTrailRules.map((r) => r.id)).toEqual([
			CLOUDTRAIL_TAMPERING_RULE_ID,
		])
	})

	it("each authentication rule's findings carry the rule's own ID", () => {
		// A failed login with 5 distinct usernames trips brute-force + spraying;
		// a successful login after 5 failures for one user trips success-after-failures.
		const scenarios = [
			{
				event: makeEvent(),
				recentFailures: makeFailures(["a", "b", "c", "d", "e"]),
			},
			{
				event: makeEvent({ status: 1 }),
				recentFailures: makeFailures(Array(5).fill("alice")),
			},
		]

		const seen = new Set<string>()

		for (const { event, recentFailures } of scenarios) {
			for (const rule of authenticationRules) {
				const result = rule.evaluate({
					event,
					recentFailures,
					configuration: makeConfig(rule.id),
				})

				if (result.detected) {
					expect(result.finding.ruleId).toBe(rule.id)
					seen.add(rule.id)
				}
			}
		}

		expect([...seen].sort()).toEqual(
			authenticationRules.map((r) => r.id).sort(),
		)
	})

	it("the CloudTrail rule's findings carry the rule's own ID", () => {
		const [rule] = cloudTrailRules

		const result = rule.evaluate({
			event: makeCloudTrailEvent(),
			configuration: makeConfig(rule.id, { category: "Cloud-Infrastructure" }),
		})

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.ruleId).toBe(CLOUDTRAIL_TAMPERING_RULE_ID)
		}
	})

	it("five failed attempts on one username: only brute-force detects", () => {
		expect(
			detectedRuleIds(makeEvent(), makeFailures(Array(5).fill("alice"))),
		).toEqual([BRUTE_FORCE_RULE_ID])
	})

	it("a successful login after five failures: only success-after-failures detects", () => {
		expect(
			detectedRuleIds(
				makeEvent({ status: 1 }),
				makeFailures(Array(5).fill("alice")),
			),
		).toEqual([SUCCESS_AFTER_FAILURES_RULE_ID])
	})

	it("a failed login never triggers success-after-failures", () => {
		expect(
			detectedRuleIds(makeEvent(), makeFailures(Array(20).fill("alice"))),
		).not.toContain(SUCCESS_AFTER_FAILURES_RULE_ID)
	})
})
