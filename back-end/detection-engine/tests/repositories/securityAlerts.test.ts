import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { EVENT_DUPLICATE, EVENT_STORED } from "../../src/constants"
import type { SecurityAlert } from "../../src/types"

const { send } = vi.hoisted(() => ({ send: vi.fn() }))

vi.mock("@aws-sdk/lib-dynamodb", async (importActual) => ({
	...(await importActual<typeof import("@aws-sdk/lib-dynamodb")>()),
	DynamoDBDocumentClient: { from: () => ({ send }) },
}))

import { storeSecurityAlert } from "../../src/repositories/securityAlerts"

const alert: SecurityAlert = {
	alertId: "alert-123",
	entityType: "ALERT",
	ruleId: "AUTH-BRUTE-FORCE-001",
	ruleName: "Test",
	severity: "high",
	status: "open",
	sourceIp: "203.0.113.10",
	windowStart: "2026-01-01T00:00:00.000Z",
	windowEnd: "2026-01-01T00:05:00.000Z",
	createdAt: "2026-01-01T00:05:00.000Z",
	description: "test",
}

beforeEach(() => {
	send.mockReset()
})

describe("storeSecurityAlert", () => {
	it("writes the alert with an idempotency condition", async () => {
		send.mockResolvedValue({})

		await expect(storeSecurityAlert(alert)).resolves.toBe(EVENT_STORED)

		const input = send.mock.calls[0][0].input
		expect(input.TableName).toBe("test-security-alerts")
		expect(input.Item).toEqual(alert)
		expect(input.ConditionExpression).toBe("attribute_not_exists(alertId)")
	})

	it("returns DUPLICATE when the alert already exists", async () => {
		send.mockRejectedValue(
			new ConditionalCheckFailedException({
				message: "exists",
				$metadata: {},
			}),
		)

		await expect(storeSecurityAlert(alert)).resolves.toBe(EVENT_DUPLICATE)
	})

	it("rethrows other DynamoDB errors", async () => {
		send.mockRejectedValue(new Error("DynamoDB unavailable"))
		await expect(storeSecurityAlert(alert)).rejects.toThrow(
			"DynamoDB unavailable",
		)
	})

	it("throws when the table is not configured", async () => {
		vi.resetModules()
		vi.stubEnv("SECURITY_ALERTS_DYNAMO_DB_TABLE", "")
		try {
			const mod = await import("../../src/repositories/securityAlerts")
			await expect(mod.storeSecurityAlert(alert)).rejects.toThrow(
				"not configured",
			)
			expect(send).not.toHaveBeenCalled()
		} finally {
			vi.unstubAllEnvs()
		}
	})
})
