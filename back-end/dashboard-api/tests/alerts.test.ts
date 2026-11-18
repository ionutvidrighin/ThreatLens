import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { beforeEach, describe, expect, it, vi } from "vitest"

const { getAlerts } = vi.hoisted(() => ({ getAlerts: vi.fn() }))

vi.mock("@/repositories/securityAlerts", () => ({
	getSecurityAlerts: getAlerts,
}))

import { handler } from "@/handler"
import { decodeCursor, encodeCursor } from "@/repositories/utils/commonHelpers"
import { SeverityFilterSchema } from "@/schemas/securityAlert.schema"

const CREATED_AT = "2026-11-12T10:05:01.000Z"
const severityKey = { alertId: "alert-1", severity: "high", createdAt: CREATED_AT }
const entityTypeKey = {
	alertId: "alert-1",
	entityType: "ALERT",
	createdAt: CREATED_AT,
}

const alerts = [{ alertId: "alert-1" }, { alertId: "alert-2" }]

const makeEvent = (
	query?: Record<string, string>,
): APIGatewayProxyEventV2 =>
	({
		routeKey: "GET /api/security-alerts",
		queryStringParameters: query,
	}) as unknown as APIGatewayProxyEventV2

const run = async (event: APIGatewayProxyEventV2) => {
	const result = (await handler(event)) as { statusCode: number; body: string }
	return { statusCode: result.statusCode, body: JSON.parse(result.body) }
}

beforeEach(() => {
	getAlerts.mockReset()
	getAlerts.mockResolvedValue({ alerts, lastEvaluatedKey: undefined })
	vi.spyOn(console, "error").mockImplementation(() => {})
})

describe("GET /api/security-alerts: defaults", () => {
	it("lists all alerts (entityType = ALERT, limit 20) when there is no query string", async () => {
		const result = await run(makeEvent(undefined))

		expect(result.statusCode).toBe(200)
		expect(getAlerts).toHaveBeenCalledWith({
			filterType: "entityType",
			filterValue: "ALERT",
			limit: 20,
			exclusiveStartKey: undefined,
		})
	})

	it("returns the alerts", async () => {
		const result = await run(makeEvent())

		expect(result.body.alertsList).toEqual(alerts)
	})

	it("omits nextCursor on the last page", async () => {
		const result = await run(makeEvent())

		expect(result.body).not.toHaveProperty("nextCursor")
	})
})

describe("GET /api/security-alerts: filters", () => {
	it.each([
		["entityType", "ALERT"],
		["ruleId", "AUTH-BRUTE-FORCE-001"],
		["sourceIp", "203.0.113.5"],
		["severity", "high"],
	])("uses the %s query param as the filter", async (name, value) => {
		await run(makeEvent({ [name]: value }))

		expect(getAlerts).toHaveBeenCalledWith(
			expect.objectContaining({ filterType: name, filterValue: value }),
		)
	})

	it("returns 400 when more than one filter is given", async () => {
		const result = await run(makeEvent({ severity: "high", sourceIp: "1.2.3.4" }))

		expect(result.statusCode).toBe(400)
		expect(result.body.message).toContain("Use only one filter at a time")
		expect(getAlerts).not.toHaveBeenCalled()
	})

	it("returns 400 for an unknown query param", async () => {
		const result = await run(makeEvent({ foo: "bar" }))

		expect(result.statusCode).toBe(400)
		expect(getAlerts).not.toHaveBeenCalled()
	})

	it("returns 400 for an invalid severity", async () => {
		const result = await run(makeEvent({ severity: "catastrophic" }))

		expect(result.statusCode).toBe(400)
		expect(getAlerts).not.toHaveBeenCalled()
	})
})

describe("GET /api/security-alerts: limit", () => {
	it("converts the limit from a string to a number", async () => {
		await run(makeEvent({ limit: "50" }))

		expect(getAlerts).toHaveBeenCalledWith(
			expect.objectContaining({ limit: 50 }),
		)
	})

	it.each(["1", "100"])("accepts the boundary limit %s", async (limit) => {
		const result = await run(makeEvent({ limit }))

		expect(result.statusCode).toBe(200)
	})

	it.each(["0", "101", "-5", "2.5", "abc"])(
		"returns 400 for the invalid limit %s",
		async (limit) => {
			const result = await run(makeEvent({ limit }))

			expect(result.statusCode).toBe(400)
			expect(getAlerts).not.toHaveBeenCalled()
		},
	)
})

describe("GET /api/security-alerts: cursor", () => {
	it("decodes the cursor into the exclusiveStartKey", async () => {
		await run(
			makeEvent({ severity: "high", cursor: encodeCursor(severityKey) }),
		)

		expect(getAlerts).toHaveBeenCalledWith(
			expect.objectContaining({ exclusiveStartKey: severityKey }),
		)
	})

	it("uses the default filter's key shape when only a cursor is given", async () => {
		await run(makeEvent({ cursor: encodeCursor(entityTypeKey) }))

		expect(getAlerts).toHaveBeenCalledWith(
			expect.objectContaining({
				filterType: "entityType",
				exclusiveStartKey: entityTypeKey,
			}),
		)
	})

	it.each([
		["garbage", "%%%garbage%%%"],
		["valid base64 that is not JSON", Buffer.from("hello").toString("base64url")],
		["a key missing its fields", encodeCursor({ alertId: "alert-1" })],
	])("returns 400 for a cursor that is %s", async (_label, cursor) => {
		const result = await run(makeEvent({ cursor }))

		expect(result.statusCode).toBe(400)
		expect(result.body.message).toBe("Invalid cursor")
		expect(getAlerts).not.toHaveBeenCalled()
	})

	it("returns 400 when the cursor belongs to a different filter", async () => {
		// a severity cursor used with the sourceIp filter has the wrong key shape
		const result = await run(
			makeEvent({ sourceIp: "203.0.113.5", cursor: encodeCursor(severityKey) }),
		)

		expect(result.statusCode).toBe(400)
		expect(getAlerts).not.toHaveBeenCalled()
	})
})

describe("GET /api/security-alerts: nextCursor", () => {
	it("encodes lastEvaluatedKey as nextCursor when more alerts exist", async () => {
		getAlerts.mockResolvedValue({ alerts, lastEvaluatedKey: severityKey })

		const result = await run(makeEvent({ severity: "high" }))

		expect(typeof result.body.nextCursor).toBe("string")
		expect(result.body.nextCursor).toMatch(/^[A-Za-z0-9_-]+$/)
		// the client can send it back unchanged and get the original key
		expect(decodeCursor(result.body.nextCursor, SeverityFilterSchema)).toEqual(
			severityKey,
		)
	})
})

describe("GET /api/security-alerts: errors", () => {
	it("returns a generic 500 when the repository fails", async () => {
		getAlerts.mockRejectedValue(new Error("DynamoDB unavailable: alerts-table"))

		const result = await run(makeEvent())

		expect(result.statusCode).toBe(500)
		expect(result.body).toEqual({ message: "Internal server error" })
	})
})
