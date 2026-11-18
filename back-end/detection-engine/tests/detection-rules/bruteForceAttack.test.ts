import { describe, expect, it } from "vitest"
import { evaluateForBruteForceAttack } from "../../src/detection-rules/evaluationAttacks/bruteForceAttack"
import {
	BRUTE_FORCE_RULE_ID,
	makeConfig,
	makeEvent,
	makeFailures,
} from "../helpers"

const THRESHOLD = 5
const WINDOW_SECONDS = 300

const failuresFor = (n: number) => makeFailures(Array(n).fill("alice"))

describe("evaluateForBruteForceAttack", () => {
	it("uses the expected default threshold", () => {
		expect(THRESHOLD).toBe(5)
	})

	it("does not detect below the threshold", () => {
		expect(evaluateForBruteForceAttack(makeEvent(), failuresFor(THRESHOLD - 1), makeConfig(BRUTE_FORCE_RULE_ID))).toEqual(
			{ detected: false },
		)
	})

	it("detects exactly at the threshold and returns a complete finding", () => {
		const event = makeEvent()
		const result = evaluateForBruteForceAttack(event, failuresFor(THRESHOLD), makeConfig(BRUTE_FORCE_RULE_ID))

		expect(result.detected).toBe(true)
		if (!result.detected) return

		expect(result.finding).toMatchObject({
			ruleId: BRUTE_FORCE_RULE_ID,
			severity: "high",
			sourceIp: event.src_endpoint.ip,
			eventTime: event.time,
			windowSeconds: WINDOW_SECONDS,
			metadata: { failedAttempts: THRESHOLD },
		})
		expect(result.finding.description).toContain(`${THRESHOLD} failed`)
	})

	it("detects above the threshold and reports the real count", () => {
		const result = evaluateForBruteForceAttack(makeEvent(), failuresFor(THRESHOLD + 3), makeConfig(BRUTE_FORCE_RULE_ID))

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.metadata.failedAttempts).toBe(THRESHOLD + 3)
		}
	})

	it("counts every attempt, including repeats of the same username", () => {
		const result = evaluateForBruteForceAttack(
			makeEvent(),
			makeFailures(Array(5).fill("bob")), makeConfig(BRUTE_FORCE_RULE_ID))
		expect(result.detected).toBe(true)
	})

	it("reports every affected account, not the triggering event's user", () => {
		const event = makeEvent({ username: "carol" })
		const history = makeFailures(["alice", "bob", "alice", "dave", "bob"])
		const result = evaluateForBruteForceAttack(event, history, makeConfig(BRUTE_FORCE_RULE_ID))

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(new Set(result.finding.metadata.usernames)).toEqual(
				new Set(["alice", "bob", "dave"]),
			)
		}
	})

	it("omits accounts for failures without a username", () => {
		const history = makeFailures(["alice", undefined, "alice", undefined, "alice"])
		const result = evaluateForBruteForceAttack(makeEvent(), history, makeConfig(BRUTE_FORCE_RULE_ID))

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(new Set(result.finding.metadata.usernames)).toEqual(new Set(["alice"]))
			expect(result.finding.metadata.failedAttempts).toBe(5)
		}
	})

	it("does not include spraying-only metadata", () => {
		const result = evaluateForBruteForceAttack(makeEvent(), failuresFor(THRESHOLD), makeConfig(BRUTE_FORCE_RULE_ID))

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.metadata).not.toHaveProperty("targetedAccounts")
		}
	})

	it("ignores successful logins even when many failures exist", () => {
		expect(evaluateForBruteForceAttack(makeEvent({ status: 1 }), failuresFor(20), makeConfig(BRUTE_FORCE_RULE_ID))).toEqual(
			{ detected: false },
		)
	})

	it("ignores non-authentication events", () => {
		const event = { ...makeEvent(), class_uid: 4001 } as never
		expect(evaluateForBruteForceAttack(event, failuresFor(20), makeConfig(BRUTE_FORCE_RULE_ID))).toEqual({
			detected: false,
		})
	})

	it("is pure: it does not touch persistence", () => {
		// Rules return findings only; persistence lives in alertOrchestrator.
		const result = evaluateForBruteForceAttack(makeEvent(), failuresFor(THRESHOLD), makeConfig(BRUTE_FORCE_RULE_ID))
		expect(result).not.toBeInstanceOf(Promise)
	})
})
