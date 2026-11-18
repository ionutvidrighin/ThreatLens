import { describe, expect, it } from "vitest"
import { evaluateForSuccessLoginAfterFailure } from "../../src/detection-rules/evaluationAttacks/successLoginAfterFailure"
import {
	ATTACKER_IP,
	makeConfig,
	makeEvent,
	makeFailures,
	SUCCESS_AFTER_FAILURES_RULE_ID,
} from "../helpers"

const THRESHOLD = 5
const WINDOW_SECONDS = 300

const config = (o: Parameters<typeof makeConfig>[1] = {}) =>
	makeConfig(SUCCESS_AFTER_FAILURES_RULE_ID, o)

const successEvent = (o: Parameters<typeof makeEvent>[0] = {}) =>
	makeEvent({ status: 1, ...o })

/** Failures for "alice" (the default user) from the default attacker IP. */
const aliceFailures = (n: number) => makeFailures(Array(n).fill("alice"))

describe("evaluateForSuccessLoginAfterFailure: detection", () => {
	it("does not detect below the threshold", () => {
		expect(
			evaluateForSuccessLoginAfterFailure(
				successEvent(),
				aliceFailures(THRESHOLD - 1),
				config(),
			),
		).toEqual({ detected: false })
	})

	it("detects exactly at the threshold and returns a complete finding", () => {
		const event = successEvent()
		const result = evaluateForSuccessLoginAfterFailure(
			event,
			aliceFailures(THRESHOLD),
			config(),
		)

		expect(result.detected).toBe(true)
		if (!result.detected) return

		expect(result.finding).toMatchObject({
			ruleId: SUCCESS_AFTER_FAILURES_RULE_ID,
			ruleName: "Successful Login After Multiple Failures",
			severity: "high",
			sourceIp: ATTACKER_IP,
			eventTime: event.time,
			windowSeconds: WINDOW_SECONDS,
			metadata: { failedAttempts: THRESHOLD, usernames: ["alice"] },
		})
		expect(result.finding.description).toContain(
			`Successful authentication for alice from ${ATTACKER_IP} following ${THRESHOLD} failed attempts`,
		)
	})

	it("reports the real count above the threshold", () => {
		const result = evaluateForSuccessLoginAfterFailure(
			successEvent(),
			aliceFailures(THRESHOLD + 3),
			config(),
		)

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.metadata.failedAttempts).toBe(THRESHOLD + 3)
		}
	})

	it("does not include spraying-only metadata", () => {
		const result = evaluateForSuccessLoginAfterFailure(
			successEvent(),
			aliceFailures(THRESHOLD),
			config(),
		)

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding.metadata).not.toHaveProperty("targetedAccounts")
		}
	})

	it("uses the configured threshold, severity and window", () => {
		const custom = config({
			threshold: 2,
			windowSeconds: 180,
			severity: "critical",
		})
		const result = evaluateForSuccessLoginAfterFailure(
			successEvent(),
			aliceFailures(2),
			custom,
		)

		expect(result.detected).toBe(true)
		if (result.detected) {
			expect(result.finding).toMatchObject({
				severity: "critical",
				windowSeconds: 180,
			})
		}
		expect(
			evaluateForSuccessLoginAfterFailure(successEvent(), aliceFailures(2), {
				...custom,
				threshold: 3,
			}),
		).toEqual({ detected: false })
	})
})

describe("evaluateForSuccessLoginAfterFailure: event eligibility", () => {
	it("ignores failed logins even when many failures exist", () => {
		expect(
			evaluateForSuccessLoginAfterFailure(
				makeEvent({ status: 2 }),
				aliceFailures(20),
				config(),
			),
		).toEqual({ detected: false })
	})
})

describe("evaluateForSuccessLoginAfterFailure: which failures count", () => {
	it("counts only failures for the user who logged in", () => {
		const history = makeFailures([
			"alice",
			"alice",
			"alice",
			"bob",
			"bob",
			"carol",
			undefined,
		])

		expect(
			evaluateForSuccessLoginAfterFailure(successEvent(), history, config()),
		).toEqual({ detected: false })
	})

	it("counts only failures from the same source IP", () => {
		const history = aliceFailures(THRESHOLD).map((failure, i) => ({
			...failure,
			sourceIp: i < 2 ? ATTACKER_IP : "198.51.100.7",
		}))

		expect(
			evaluateForSuccessLoginAfterFailure(successEvent(), history, config()),
		).toEqual({ detected: false })
	})

	it("includes the window start boundary and excludes older failures", () => {
		const event = successEvent()
		const windowStart = event.time - WINDOW_SECONDS * 1000
		const offsets = [0, -1, 1] // at boundary, just outside, just inside
		const history = aliceFailures(3).map((failure, i) => ({
			...failure,
			eventTime: new Date(windowStart + offsets[i]).toISOString(),
		}))

		const twoCount = evaluateForSuccessLoginAfterFailure(
			event,
			history,
			config({ threshold: 2 }),
		)
		expect(twoCount.detected).toBe(true)
		if (twoCount.detected) {
			expect(twoCount.finding.metadata.failedAttempts).toBe(2)
		}

		expect(
			evaluateForSuccessLoginAfterFailure(
				event,
				history,
				config({ threshold: 3 }),
			),
		).toEqual({ detected: false })
	})

	it("excludes failures at or after the login time", () => {
		const event = successEvent()
		const offsets = [-1, 0, 1] // just before, same instant, after
		const history = aliceFailures(3).map((failure, i) => ({
			...failure,
			eventTime: new Date(event.time + offsets[i]).toISOString(),
		}))

		const oneCount = evaluateForSuccessLoginAfterFailure(
			event,
			history,
			config({ threshold: 1 }),
		)
		expect(oneCount.detected).toBe(true)
		if (oneCount.detected) {
			expect(oneCount.finding.metadata.failedAttempts).toBe(1)
		}

		expect(
			evaluateForSuccessLoginAfterFailure(
				event,
				history,
				config({ threshold: 2 }),
			),
		).toEqual({ detected: false })
	})

	it("ignores failures with invalid timestamps", () => {
		const history = aliceFailures(THRESHOLD).map((failure, i) =>
			i === 0 ? { ...failure, eventTime: "not-a-date" } : failure,
		)

		expect(
			evaluateForSuccessLoginAfterFailure(successEvent(), history, config()),
		).toEqual({ detected: false })
	})

	it("returns no detection for an empty history", () => {
		expect(
			evaluateForSuccessLoginAfterFailure(successEvent(), [], config()),
		).toEqual({ detected: false })
	})
})

