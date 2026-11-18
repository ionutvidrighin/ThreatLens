import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { getSecurityAlerts } from "@/repositories/securityAlerts"

const alert = {
	alertId: "alert-1",
	entityType: "ALERT",
	ruleId: "AUTH-BRUTE-FORCE-001",
	ruleName: "Brute force",
	severity: "high",
	status: "open",
	sourceIp: "203.0.113.5",
	windowStart: "2026-11-12T10:00:00.000Z",
	windowEnd: "2026-11-12T10:05:00.000Z",
	createdAt: "2026-11-12T10:05:01.000Z",
	description: "6 failed attempts",
	failedAttempts: 6,
}

const CREATED_AT = "2026-11-12T10:05:01.000Z"

// One valid pagination key per index: table key (alertId) + index keys.
const pageKeys = {
	entityType: { alertId: "alert-1", entityType: "ALERT", createdAt: CREATED_AT },
	ruleId: {
		alertId: "alert-1",
		ruleId: "AUTH-BRUTE-FORCE-001",
		createdAt: CREATED_AT,
	},
	sourceIp: { alertId: "alert-1", sourceIp: "203.0.113.5", createdAt: CREATED_AT },
	severity: { alertId: "alert-1", severity: "high", createdAt: CREATED_AT },
} as const

const mockSend = (response: object) =>
	vi
		.spyOn(DynamoDBDocumentClient.prototype, "send")
		.mockResolvedValue(response as never)

const sentInput = (send: ReturnType<typeof mockSend>) => {
	const command = send.mock.calls[0]?.[0]
	expect(command).toBeInstanceOf(QueryCommand)
	return (command as QueryCommand).input
}

beforeEach(() => {
	vi.stubEnv("ALERTS_TABLE_NAME", "alerts-table")
})

afterEach(() => {
	vi.restoreAllMocks()
	vi.unstubAllEnvs()
})

describe("getSecurityAlerts: the query", () => {
	it("queries the entityType index newest-first with the given page size", async () => {
		const send = mockSend({ Items: [alert] })

		await getSecurityAlerts({
			filterType: "entityType",
			filterValue: "ALERT",
			limit: 20,
		})

		expect(sentInput(send)).toMatchObject({
			TableName: "alerts-table",
			IndexName: "query-by-entityType",
			KeyConditionExpression: "entityType = :entityTypeValue",
			ExpressionAttributeValues: { ":entityTypeValue": "ALERT" },
			ScanIndexForward: false,
			Limit: 20,
		})
		expect(sentInput(send).ExclusiveStartKey).toBeUndefined()
	})

	it.each([
		["entityType", "ALERT", "query-by-entityType", ":entityTypeValue"],
		["ruleId", "AUTH-BRUTE-FORCE-001", "query-by-ruleId", ":ruleIdValue"],
		["sourceIp", "203.0.113.5", "query-by-sourceIp", ":sourceIpValue"],
		["severity", "high", "query-by-severity", ":severityValue"],
	] as const)(
		"uses the right index and condition for the %s filter",
		async (filterType, filterValue, indexName, placeholder) => {
			const send = mockSend({ Items: [] })

			await getSecurityAlerts({ filterType, filterValue, limit: 10 })

			expect(sentInput(send)).toMatchObject({
				IndexName: indexName,
				KeyConditionExpression: `${filterType} = ${placeholder}`,
				ExpressionAttributeValues: { [placeholder]: filterValue },
			})
		},
	)

	it("passes exclusiveStartKey to DynamoDB when continuing a listing", async () => {
		const send = mockSend({ Items: [] })

		await getSecurityAlerts({
			filterType: "severity",
			filterValue: "high",
			limit: 20,
			exclusiveStartKey: pageKeys.severity,
		})

		expect(sentInput(send).ExclusiveStartKey).toEqual(pageKeys.severity)
	})
})

describe("getSecurityAlerts: the result", () => {
	it("returns the alerts and no cursor on the last page", async () => {
		mockSend({ Items: [alert] })

		const page = await getSecurityAlerts({
			filterType: "entityType",
			filterValue: "ALERT",
			limit: 20,
		})

		expect(page.alerts).toEqual([alert])
		expect(page.lastEvaluatedKey).toBeUndefined()
	})

	it("returns an empty list when DynamoDB returns no items", async () => {
		mockSend({})

		expect(
			await getSecurityAlerts({
				filterType: "entityType",
				filterValue: "ALERT",
				limit: 20,
			}),
		).toEqual({ alerts: [], lastEvaluatedKey: undefined })
	})

	it.each([
		["entityType", "ALERT"],
		["ruleId", "AUTH-BRUTE-FORCE-001"],
		["sourceIp", "203.0.113.5"],
		["severity", "high"],
	] as const)(
		"returns lastEvaluatedKey for the %s filter so the caller can request the next page",
		async (filterType, filterValue) => {
			mockSend({ Items: [alert], LastEvaluatedKey: pageKeys[filterType] })

			const page = await getSecurityAlerts({
				filterType,
				filterValue,
				limit: 1,
			})

			expect(page.lastEvaluatedKey).toEqual(pageKeys[filterType])
		},
	)

	it("throws when the key DynamoDB returns does not fit the filter's index", async () => {
		// a severity-shaped key coming back from the entityType index is not valid
		mockSend({ Items: [alert], LastEvaluatedKey: pageKeys.severity })

		await expect(
			getSecurityAlerts({
				filterType: "entityType",
				filterValue: "ALERT",
				limit: 1,
			}),
		).rejects.toThrow()
	})
})

describe("getSecurityAlerts: configuration", () => {
	it("throws when the table name env var is missing", async () => {
		vi.stubEnv("ALERTS_TABLE_NAME", "")

		await expect(
			getSecurityAlerts({
				filterType: "entityType",
				filterValue: "ALERT",
				limit: 20,
			}),
		).rejects.toThrow("ALERTS_TABLE_NAME env var is missing")
	})
})
