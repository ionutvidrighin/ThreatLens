import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const { send } = vi.hoisted(() => ({ send: vi.fn() }))

vi.mock("@aws-sdk/lib-dynamodb", () => ({
	DynamoDBDocumentClient: { from: () => ({ send }) },
	UpdateCommand: class {
		constructor(public input: unknown) {}
	},
}))

import { HttpError, RuleUpdateConflictError } from "@/errors"
import { updateDetectionRule } from "@/repositories/detectionRules"
import {
	BRUTE_FORCE_RULE_ID,
	CLOUDTRAIL_TAMPERING_RULE_ID,
	ruleConfig,
} from "../fixtures"

const TABLE = "test-detection-rules"
const RULE = BRUTE_FORCE_RULE_ID
const PREVIOUS = "2026-01-01T00:00:00.000Z"
const NOW = "2026-06-01T12:00:00.000Z"

const stored = (o: Record<string, unknown> = {}) =>
	ruleConfig(RULE, { updatedAt: NOW, ...o })

const input = (o: Record<string, unknown> = {}) =>
	({ threshold: 10, previouslyUpdatedAt: PREVIOUS, ...o }) as never

const sentInput = () => send.mock.calls[0][0].input

beforeEach(() => {
	send.mockReset()
	send.mockResolvedValue({ Attributes: stored({ threshold: 10 }) })
	vi.stubEnv("DETECTION_RULES_TABLE_NAME", TABLE)
	vi.useFakeTimers()
	vi.setSystemTime(new Date(NOW))
})

afterEach(() => {
	vi.useRealTimers()
	vi.unstubAllEnvs()
})

describe("updateDetectionRule: preconditions", () => {
	it("throws when DETECTION_RULES_TABLE_NAME is missing", async () => {
		vi.stubEnv("DETECTION_RULES_TABLE_NAME", "")

		await expect(updateDetectionRule(RULE, input())).rejects.toThrow(
			"DETECTION_RULES_TABLE_NAME env var is missing",
		)
		expect(send).not.toHaveBeenCalled()
	})

	it("re-validates the update and rejects invalid input", async () => {
		await expect(
			updateDetectionRule(RULE, input({ threshold: 0 })),
		).rejects.toThrow()
		await expect(
			updateDetectionRule(RULE, input({ ruleId: "x" })),
		).rejects.toThrow()
		expect(send).not.toHaveBeenCalled()
	})

	it("rejects an update with no editable fields", async () => {
		await expect(
			updateDetectionRule(RULE, { previouslyUpdatedAt: PREVIOUS } as never),
		).rejects.toThrow("At least one editable field must be provided")
		expect(send).not.toHaveBeenCalled()
	})
})

describe("updateDetectionRule: the DynamoDB update", () => {
	it("targets the rule's key in the configured table", async () => {
		await updateDetectionRule(RULE, input())

		expect(send).toHaveBeenCalledOnce()
		expect(sentInput().TableName).toBe(TABLE)
		expect(sentInput().Key).toEqual({ ruleId: RULE })
		expect(sentInput().ReturnValues).toBe("ALL_NEW")
	})

	it("sets only the provided fields plus updatedAt", async () => {
		await updateDetectionRule(RULE, input({ threshold: 10 }))

		expect(sentInput().UpdateExpression).toBe(
			"SET #updatedAt = :updatedAt, #threshold = :threshold",
		)
		expect(sentInput().ExpressionAttributeNames).toEqual({
			"#updatedAt": "updatedAt",
			"#threshold": "threshold",
		})
		expect(sentInput().ExpressionAttributeValues).toMatchObject({
			":threshold": 10,
		})
		expect(sentInput().ExpressionAttributeValues).not.toHaveProperty(
			":enabled",
		)
	})

	it("sets every editable field when all are provided", async () => {
		await updateDetectionRule(
			RULE,
			input({
				enabled: false,
				threshold: 3,
				windowSeconds: 120,
				severity: "low",
			}),
		)

		expect(sentInput().ExpressionAttributeValues).toMatchObject({
			":enabled": false,
			":threshold": 3,
			":windowSeconds": 120,
			":severity": "low",
		})
		for (const field of ["enabled", "threshold", "windowSeconds", "severity"]) {
			expect(sentInput().UpdateExpression).toContain(`#${field} = :${field}`)
		}
	})

	it("writes enabled: false (a falsy value must not be dropped)", async () => {
		await updateDetectionRule(RULE, input({ enabled: false, threshold: undefined }))

		expect(sentInput().UpdateExpression).toContain("#enabled = :enabled")
		expect(sentInput().ExpressionAttributeValues[":enabled"]).toBe(false)
	})

	it("never writes previouslyUpdatedAt as a field", async () => {
		await updateDetectionRule(RULE, input())

		expect(sentInput().UpdateExpression).not.toContain("previouslyUpdatedAt =")
		expect(sentInput().ExpressionAttributeNames).not.toHaveProperty(
			"#previouslyUpdatedAt",
		)
	})

	it("uses optimistic concurrency on updatedAt", async () => {
		await updateDetectionRule(RULE, input())

		expect(sentInput().ConditionExpression).toBe("#updatedAt = :previouslyUpdatedAt")
		expect(sentInput().ExpressionAttributeValues[":previouslyUpdatedAt"]).toBe(
			PREVIOUS,
		)
	})
})

describe("updateDetectionRule: concurrency token", () => {
	it("stamps the current time as the new updatedAt", async () => {
		await updateDetectionRule(RULE, input())

		expect(sentInput().ExpressionAttributeValues[":updatedAt"]).toBe(NOW)
	})

	it("always advances past previouslyUpdatedAt, even within the same millisecond", async () => {
		vi.setSystemTime(new Date(PREVIOUS))

		await updateDetectionRule(RULE, input())

		expect(sentInput().ExpressionAttributeValues[":updatedAt"]).toBe(
			"2026-01-01T00:00:00.001Z",
		)
	})

	it("advances past previouslyUpdatedAt when the clock is behind it", async () => {
		vi.setSystemTime(new Date("2025-01-01T00:00:00.000Z"))

		await updateDetectionRule(RULE, input())

		expect(sentInput().ExpressionAttributeValues[":updatedAt"]).toBe(
			"2026-01-01T00:00:00.001Z",
		)
	})
})

describe("updateDetectionRule: results and errors", () => {
	it("returns the updated, validated configuration", async () => {
		const updated = stored({ threshold: 10, updatedAt: NOW })
		send.mockResolvedValue({ Attributes: updated })

		await expect(updateDetectionRule(RULE, input())).resolves.toEqual(
			updated,
		)
	})

	it("fails if DynamoDB returns attributes that are not a valid config", async () => {
		send.mockResolvedValue({ Attributes: stored({ threshold: 0 }) })

		await expect(updateDetectionRule(RULE, input())).rejects.toThrow()
	})

	it("fails if DynamoDB returns no attributes", async () => {
		send.mockResolvedValue({})

		await expect(updateDetectionRule(RULE, input())).rejects.toThrow()
	})

	it("maps a failed condition to RuleUpdateConflictError", async () => {
		const error = new Error("The conditional request failed")
		error.name = "ConditionalCheckFailedException"
		send.mockRejectedValue(error)

		const promise = updateDetectionRule(RULE, input())

		await expect(promise).rejects.toBeInstanceOf(RuleUpdateConflictError)
		await expect(promise).rejects.toThrow("reload before retrying")
	})

	it("rethrows other DynamoDB errors unchanged", async () => {
		const error = new Error("throttled")
		error.name = "ProvisionedThroughputExceededException"
		send.mockRejectedValue(error)

		const promise = updateDetectionRule(RULE, input())

		await expect(promise).rejects.toBe(error)
		await expect(promise).rejects.not.toBeInstanceOf(RuleUpdateConflictError)
	})
})

describe("updateDetectionRule: CloudTrail tampering rule", () => {
	// This rule only exposes the enable/disable toggle; the other fields are
	// ignored even if the request carries them.
	const TAMPERING = CLOUDTRAIL_TAMPERING_RULE_ID

	beforeEach(() => {
		send.mockResolvedValue({
			Attributes: ruleConfig(TAMPERING, {
				category: "Cloud-Infrastructure",
				enabled: false,
				updatedAt: NOW,
			}),
		})
	})

	it("writes only updatedAt and enabled, ignoring every other field", async () => {
		await updateDetectionRule(
			TAMPERING,
			input({
				enabled: false,
				threshold: 10,
				windowSeconds: 60,
				severity: "low",
			}),
		)

		expect(sentInput().Key).toEqual({ ruleId: TAMPERING })
		expect(sentInput().UpdateExpression).toBe(
			"SET #updatedAt = :updatedAt, #enabled = :enabled",
		)
		expect(sentInput().ExpressionAttributeNames).toEqual({
			"#updatedAt": "updatedAt",
			"#enabled": "enabled",
		})
		expect(sentInput().ExpressionAttributeValues).toEqual({
			":updatedAt": NOW,
			":enabled": false,
			":previouslyUpdatedAt": PREVIOUS,
		})
	})

	it("can re-enable the rule", async () => {
		await updateDetectionRule(TAMPERING, input({ enabled: true }))

		expect(sentInput().ExpressionAttributeValues[":enabled"]).toBe(true)
	})

	it("rejects a request without `enabled` and never writes", async () => {
		const promise = updateDetectionRule(
			TAMPERING,
			input({ threshold: undefined, severity: "low" }),
		)

		await expect(promise).rejects.toBeInstanceOf(HttpError)
		await expect(promise).rejects.toThrow(
			"Only the enabled field can be changed for this rule",
		)
		expect(send).not.toHaveBeenCalled()
	})

	it("keeps the optimistic-lock condition", async () => {
		await updateDetectionRule(TAMPERING, input({ enabled: false }))

		expect(sentInput().ConditionExpression).toBe(
			"#updatedAt = :previouslyUpdatedAt",
		)
	})

	it("does not affect how other rules are updated", async () => {
		await updateDetectionRule(RULE, input({ threshold: 10, severity: "low" }))

		expect(sentInput().UpdateExpression).toBe(
			"SET #updatedAt = :updatedAt, #threshold = :threshold, #severity = :severity",
		)
	})
})
