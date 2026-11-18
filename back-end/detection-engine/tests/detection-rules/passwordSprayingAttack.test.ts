import { describe, expect, it } from "vitest"
import { evaluateForPasswordSprayingAttack } from "../../src/detection-rules/evaluationAttacks/passwordSprayingAttack"
import {
	makeConfig,
	makeEvent,
	makeFailures,
	PASSWORD_SPRAYING_RULE_ID,
} from "../helpers"

const PASSWORD_SPRAYING_THRESHOLD = 5
const WINDOW_SECONDS = 300

const distinct = (n: number) => Array.from({ length: n }, (_, i) => `user${i}`)

describe("evaluateForPasswordSprayingAttack", () => {
	it("does not detect below the distinct-account threshold", () => {
		const result = evaluateForPasswordSprayingAttack(
			makeEvent(),
			makeFailures(distinct(PASSWORD_SPRAYING_THRESHOLD - 1)), makeConfig(PASSWORD_SPRAYING_RULE_ID))
		expect(result).toEqual({ detected: false })
	})

	it("detects exactly at the threshold and returns a complete finding", () => {
		const names = distinct(PASSWORD_SPRAYING_THRESHOLD)
		const event = makeEvent()
		const result = evaluateForPasswordSprayingAttack(event, makeFailures(names), makeConfig(PASSWORD_SPRAYING_RULE_ID))

		expect(result.detected).toBe(true)
		if (!result.detected) return

		expect(result.finding).toMatchObject({
			ruleId: PASSWORD_SPRAYING_RULE_ID,
			severity: "high",
			sourceIp: event.src_endpoint.ip,
			eventTime: event.time,
			windowSeconds: WINDOW_SECONDS,
			metadata: {
				targetedAccounts: PASSWORD_SPRAYING_THRESHOLD,
				usernames: names,
			},
		})
	})

	it("counts duplicate usernames once", () => {
		const failures = makeFailures([...distinct(4), ...Array(20).fill("user0")])
		expect(evaluateForPasswordSprayingAttack(makeEvent(), failures, makeConfig(PASSWORD_SPRAYING_RULE_ID))).toEqual({
			detected: false,
		})
	})

	it("never detects many attempts against a single username", () => {
		const result = evaluateForPasswordSprayingAttack(
			makeEvent(),
			makeFailures(Array(50).fill("alice")), makeConfig(PASSWORD_SPRAYING_RULE_ID))
		expect(result).toEqual({ detected: false })
	})

	it("trims whitespace and ignores blank or missing usernames", () => {
		// 5 raw distinct strings collapse to far fewer real accounts.
		const sparse = makeFailures([" a ", "a", "a  ", "", "   ", undefined, "b"])
		expect(evaluateForPasswordSprayingAttack(makeEvent(), sparse, makeConfig(PASSWORD_SPRAYING_RULE_ID)).detected).toBe(false)

		const enough = makeFailures([
			" u1 ",
			"u1",
			"u2",
			"u3",
			"",
			undefined,
			"u4 ",
			"u5",
		])
		const result = evaluateForPasswordSprayingAttack(makeEvent(), enough, makeConfig(PASSWORD_SPRAYING_RULE_ID))
		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.metadata.usernames).toEqual([
				"u1",
				"u2",
				"u3",
				"u4",
				"u5",
			])
			expect(result.finding.metadata.targetedAccounts).toBe(5)
		}
	})

	it("does not include brute-force-only metadata", () => {
		const result = evaluateForPasswordSprayingAttack(
			makeEvent(),
			makeFailures(distinct(5)), makeConfig(PASSWORD_SPRAYING_RULE_ID))
		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.metadata).not.toHaveProperty("failedAttempts")
		}
	})

	it("ignores successful logins", () => {
		const result = evaluateForPasswordSprayingAttack(
			makeEvent({ status: 1 }),
			makeFailures(distinct(10)), makeConfig(PASSWORD_SPRAYING_RULE_ID))
		expect(result).toEqual({ detected: false })
	})

	it("ignores non-authentication events", () => {
		const event = { ...makeEvent(), class_uid: 4001 } as never
		expect(
			evaluateForPasswordSprayingAttack(event, makeFailures(distinct(10)), makeConfig(PASSWORD_SPRAYING_RULE_ID)),
		).toEqual({ detected: false })
	})
})
