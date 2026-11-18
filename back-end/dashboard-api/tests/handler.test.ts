import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { beforeEach, describe, expect, it, vi } from "vitest"

const { getRules } = vi.hoisted(() => ({ getRules: vi.fn() }))

vi.mock("@/repositories/detectionRules", () => ({
	getDetectionRules: getRules,
	updateDetectionRule: vi.fn(),
}))

import { handler } from "@/handler"

// API Gateway HTTP API v2 puts "METHOD /path" in `routeKey`; the router uses it.
const makeEvent = (routeKey = "GET /api/detection-rules"): APIGatewayProxyEventV2 =>
	({ routeKey }) as APIGatewayProxyEventV2

const rules = [
	{
		ruleId: "AUTH-BRUTE-FORCE-001",
		enabled: true,
		threshold: 5,
		windowSeconds: 300,
		severity: "high",
		updatedAt: "2026-01-01T00:00:00.000Z",
	},
	{
		ruleId: "AUTH-PASSWORD-SPRAYING-001",
		enabled: false,
		threshold: 10,
		windowSeconds: 600,
		severity: "critical",
		updatedAt: "2026-01-02T00:00:00.000Z",
	},
]

// Treat optional response properties as required for assertions in these tests.
const run = async (event: APIGatewayProxyEventV2) =>
	(await handler(event)) as {
		statusCode: number
		headers: Record<string, string>
		body: string
	}

beforeEach(() => {
	getRules.mockReset()
	vi.spyOn(console, "error").mockImplementation(() => {})
})

describe("GET /api/detection-rules", () => {
	it("returns 200 with all rule configurations", async () => {
		getRules.mockResolvedValue(rules)

		const result = await run(makeEvent())

		expect(result.statusCode).toBe(200)
		expect(JSON.parse(result.body)).toEqual(rules)
		expect(getRules).toHaveBeenCalledOnce()
	})

	it("responds with a JSON content type", async () => {
		getRules.mockResolvedValue(rules)

		const result = await run(makeEvent())

		expect(result.headers).toEqual({ "Content-Type": "application/json" })
	})

	it("returns an empty list as a valid 200 response", async () => {
		getRules.mockResolvedValue([])

		const result = await run(makeEvent())

		expect(result.statusCode).toBe(200)
		expect(JSON.parse(result.body)).toEqual([])
	})
})

describe("routing", () => {
	it.each([
		"POST /api/detection-rules",
		"PUT /api/detection-rules",
		"DELETE /api/detection-rules",
		"GET /",
		"GET /api/rule",
		"GET /api/Detection-Rules",
		"GET /api/detection-rules/AUTH-BRUTE-FORCE-001",
		"get /api/detection-rules",
		"$default",
	])("returns 404 for the unknown route %s without reading rules", async (key) => {
		const result = await run(makeEvent(key))

		expect(result.statusCode).toBe(404)
		expect(JSON.parse(result.body)).toEqual({ message: "Route not found" })
		expect(getRules).not.toHaveBeenCalled()
	})

	it("sets a JSON content type on 404 responses", async () => {
		const result = await run(makeEvent("POST /api/detection-rules"))

		expect(result.headers).toEqual({ "Content-Type": "application/json" })
	})
})

describe("error handling", () => {
	it("returns 500 with a generic message when loading rules fails", async () => {
		getRules.mockRejectedValue(new Error("DynamoDB unavailable"))

		const result = await run(makeEvent())

		expect(result.statusCode).toBe(500)
		expect(JSON.parse(result.body)).toEqual({
			message: "Internal server error",
		})
	})

	it("does not leak internal error details to the client", async () => {
		getRules.mockRejectedValue(
			new Error("Missing detection rule configurations: AUTH-BRUTE-FORCE-001"),
		)

		const result = await run(makeEvent())

		expect(result.body).not.toContain("AUTH-BRUTE-FORCE-001")
		expect(result.body).not.toContain("Missing")
	})

	it("logs the underlying error for diagnosis", async () => {
		const error = new Error("DynamoDB unavailable")
		getRules.mockRejectedValue(error)

		await run(makeEvent())

		expect(console.error).toHaveBeenCalledWith({
			detail: "Unhandled error",
			error,
		})
	})

	it("returns 500 for non-Error rejections", async () => {
		getRules.mockRejectedValue("boom")

		const result = await run(makeEvent())

		expect(result.statusCode).toBe(500)
	})

	it("sets a JSON content type on 500 responses", async () => {
		getRules.mockRejectedValue(new Error("x"))

		const result = await run(makeEvent())

		expect(result.headers).toEqual({ "Content-Type": "application/json" })
	})
})
