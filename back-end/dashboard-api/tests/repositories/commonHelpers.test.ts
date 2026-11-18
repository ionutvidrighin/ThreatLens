import { describe, expect, it } from "vitest"
import { z } from "zod"
import { HttpError } from "@/errors"
import {
	buildRuleUpdateExpression,
	decodeCursor,
	encodeCursor,
} from "@/repositories/utils/commonHelpers"
import { BRUTE_FORCE_RULE_ID, CLOUDTRAIL_TAMPERING_RULE_ID } from "../fixtures"

const KeySchema = z.object({
	alertId: z.string().min(1),
	createdAt: z.string().min(1),
})
const key = { alertId: "alert-1", createdAt: "2026-11-12T10:05:01.000Z" }

describe("encodeCursor / decodeCursor", () => {
	it("round-trips a key object through the opaque string", () => {
		expect(decodeCursor(encodeCursor(key), KeySchema)).toEqual(key)
	})

	it("produces a URL-safe string (no +, / or =)", () => {
		const cursor = encodeCursor({ ...key, alertId: "???>>>~~~" })

		expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/)
	})

	it.each([
		["not base64 / not JSON", "%%%not-a-cursor%%%"],
		["valid base64 but not JSON", Buffer.from("hello").toString("base64url")],
		["JSON that is not an object", Buffer.from("42").toString("base64url")],
		["an object missing fields", encodeCursor({ alertId: "alert-1" })],
		["an empty string", ""],
	])("rejects %s with a 400", (_label, cursor) => {
		const act = () => decodeCursor(cursor, KeySchema)

		expect(act).toThrow(HttpError)
		expect(act).toThrow("Invalid cursor")
		try {
			act()
		} catch (error) {
			expect((error as HttpError).statusCode).toBe(400)
		}
	})
})

const PREVIOUS = "2026-11-11T10:00:00.000Z"
const NOW = Date.parse("2026-11-12T00:00:00.000Z")
const RULE = BRUTE_FORCE_RULE_ID

describe("buildRuleUpdateExpression", () => {
	it("builds placeholders for each provided field plus updatedAt", () => {
		const result = buildRuleUpdateExpression(
			RULE,
			{ threshold: 8, enabled: false },
			PREVIOUS,
			NOW,
		)

		expect(result.UpdateExpression).toBe(
			"SET #updatedAt = :updatedAt, #threshold = :threshold, #enabled = :enabled",
		)
		expect(result.ExpressionAttributeNames).toEqual({
			"#updatedAt": "updatedAt",
			"#threshold": "threshold",
			"#enabled": "enabled",
		})
		expect(result.ExpressionAttributeValues).toEqual({
			":updatedAt": "2026-11-12T00:00:00.000Z",
			":previouslyUpdatedAt": PREVIOUS,
			":threshold": 8,
			":enabled": false,
		})
	})

	it("guards the write with an optimistic-lock condition on updatedAt", () => {
		const result = buildRuleUpdateExpression(RULE, { threshold: 2 }, PREVIOUS, NOW)

		expect(result.ConditionExpression).toBe("#updatedAt = :previouslyUpdatedAt")
		expect(result.ExpressionAttributeNames).toHaveProperty("#updatedAt")
		expect(result.ExpressionAttributeValues).toHaveProperty(
			":previouslyUpdatedAt",
			PREVIOUS,
		)
	})

	it("keeps enabled: false (falsy values are real changes)", () => {
		const result = buildRuleUpdateExpression(RULE, { enabled: false }, PREVIOUS, NOW)

		expect(result.ExpressionAttributeValues[":enabled"]).toBe(false)
	})

	it("skips undefined fields", () => {
		const result = buildRuleUpdateExpression(
			RULE,
			{ severity: "high", threshold: undefined },
			PREVIOUS,
			NOW,
		)

		expect(result.UpdateExpression).not.toContain("threshold")
		expect(result.ExpressionAttributeNames).not.toHaveProperty("#threshold")
	})

	it("advances updatedAt past the expected value when the clock has not moved", () => {
		const result = buildRuleUpdateExpression(
			RULE,
			{ threshold: 2 },
			PREVIOUS,
			Date.parse(PREVIOUS),
		)

		expect(result.ExpressionAttributeValues[":updatedAt"]).toBe(
			"2026-11-11T10:00:00.001Z",
		)
	})
})

describe("buildRuleUpdateExpression: CloudTrail tampering rule", () => {
	const TAMPERING = CLOUDTRAIL_TAMPERING_RULE_ID

	it("only writes updatedAt and enabled, whatever else was sent", () => {
		const result = buildRuleUpdateExpression(
			TAMPERING,
			{ enabled: false, threshold: 8, windowSeconds: 60, severity: "low" },
			PREVIOUS,
			NOW,
		)

		expect(result.UpdateExpression).toBe(
			"SET #updatedAt = :updatedAt, #enabled = :enabled",
		)
		expect(result.ExpressionAttributeNames).toEqual({
			"#updatedAt": "updatedAt",
			"#enabled": "enabled",
		})
		expect(result.ExpressionAttributeValues).toEqual({
			":updatedAt": "2026-11-12T00:00:00.000Z",
			":previouslyUpdatedAt": PREVIOUS,
			":enabled": false,
		})
	})

	it("rejects a request without `enabled` instead of disabling the rule", () => {
		const act = () =>
			buildRuleUpdateExpression(TAMPERING, { severity: "low" }, PREVIOUS, NOW)

		expect(act).toThrow(HttpError)
		expect(act).toThrow("Only the enabled field can be changed for this rule")
		try {
			act()
		} catch (error) {
			expect((error as HttpError).statusCode).toBe(400)
		}
	})

	it("treats enabled: false as provided (it is a real change)", () => {
		const result = buildRuleUpdateExpression(
			TAMPERING,
			{ enabled: false },
			PREVIOUS,
			NOW,
		)

		expect(result.ExpressionAttributeValues[":enabled"]).toBe(false)
	})

	it("still guards the write with the optimistic-lock condition", () => {
		const result = buildRuleUpdateExpression(
			TAMPERING,
			{ enabled: true },
			PREVIOUS,
			NOW,
		)

		expect(result.ConditionExpression).toBe("#updatedAt = :previouslyUpdatedAt")
	})

	it("advances updatedAt past the expected value when the clock has not moved", () => {
		const result = buildRuleUpdateExpression(
			TAMPERING,
			{ enabled: true },
			PREVIOUS,
			Date.parse(PREVIOUS),
		)

		expect(result.ExpressionAttributeValues[":updatedAt"]).toBe(
			"2026-11-11T10:00:00.001Z",
		)
	})

	it("leaves other rules free to change every editable field", () => {
		const result = buildRuleUpdateExpression(
			RULE,
			{ enabled: true, threshold: 8, windowSeconds: 60, severity: "low" },
			PREVIOUS,
			NOW,
		)

		expect(Object.keys(result.ExpressionAttributeNames).sort()).toEqual([
			"#enabled",
			"#severity",
			"#threshold",
			"#updatedAt",
			"#windowSeconds",
		])
	})
})
