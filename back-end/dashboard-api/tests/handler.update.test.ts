import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { beforeEach, describe, expect, it, vi } from "vitest"

const { getRules, updateRule } = vi.hoisted(() => ({
	getRules: vi.fn(),
	updateRule: vi.fn(),
}))

vi.mock("@/repositories/detectionRules", () => ({
	getDetectionRules: getRules,
	updateDetectionRule: updateRule,
}))

import { RuleNotFoundError, RuleUpdateConflictError } from "@/errors"
import { handler } from "@/handler"
import { DETECTION_RULE_IDS } from "@/repositories/utils/detectionRulesHelpers"
import {
	BRUTE_FORCE_RULE_ID,
	CLOUDTRAIL_TAMPERING_RULE_ID,
	ruleConfig,
} from "./fixtures"

const RULE = BRUTE_FORCE_RULE_ID
const PREVIOUS = "2026-01-01T00:00:00.000Z"

// The router matches on `routeKey`; the rule ID comes from `pathParameters`.
const makeEvent = (o: {
	routeKey?: string
	ruleId?: string | null
	body?: unknown
	base64?: boolean
}): APIGatewayProxyEventV2 => {
	const raw =
		typeof o.body === "string" || o.body === undefined
			? (o.body as string | undefined)
			: JSON.stringify(o.body)
	const ruleId = o.ruleId === undefined ? RULE : o.ruleId
	return {
		routeKey: o.routeKey ?? "PATCH /api/detection-rules/{ruleId}",
		pathParameters: ruleId === null ? undefined : { ruleId },
		body:
			o.base64 && raw !== undefined
				? Buffer.from(raw).toString("base64")
				: raw,
		isBase64Encoded: o.base64 ?? false,
	} as APIGatewayProxyEventV2
}

const run = async (event: APIGatewayProxyEventV2) =>
	(await handler(event)) as {
		statusCode: number
		headers: Record<string, string>
		body: string
	}

const validBody = { threshold: 10, previouslyUpdatedAt: PREVIOUS }
const updatedRule = ruleConfig(RULE, {
	threshold: 10,
	updatedAt: "2026-06-01T00:00:00.000Z",
})

beforeEach(() => {
	getRules.mockReset()
	updateRule.mockReset()
	updateRule.mockResolvedValue(updatedRule)
	vi.spyOn(console, "error").mockImplementation(() => {})
})

describe("PATCH /api/detection-rules/{ruleId}: success", () => {
	it("returns 200 with the updated rule", async () => {
		const result = await run(makeEvent({ body: validBody }))

		expect(result.statusCode).toBe(200)
		expect(result.headers).toEqual({ "Content-Type": "application/json" })
		expect(JSON.parse(result.body)).toEqual({ rule: updatedRule })
	})

	it("passes the rule ID and the parsed body to the repository", async () => {
		await run(makeEvent({ body: { ...validBody, enabled: false } }))

		expect(updateRule).toHaveBeenCalledOnce()
		expect(updateRule).toHaveBeenCalledWith(RULE, {
			...validBody,
			enabled: false,
		})
	})

	it("works for every known rule ID", async () => {
		for (const [index, id] of DETECTION_RULE_IDS.entries()) {
			updateRule.mockResolvedValueOnce({ ...updatedRule, ruleId: id })
			const result = await run(makeEvent({ ruleId: id, body: validBody }))
			expect(result.statusCode).toBe(200)
			expect(updateRule).toHaveBeenNthCalledWith(index + 1, id, validBody)
			expect(JSON.parse(result.body)).toEqual({
				rule: { ...updatedRule, ruleId: id },
			})
		}
		expect(updateRule).toHaveBeenCalledTimes(DETECTION_RULE_IDS.length)
	})

	it("lets the CloudTrail tampering rule be toggled through the same route", async () => {
		const toggled = ruleConfig(CLOUDTRAIL_TAMPERING_RULE_ID, {
			category: "Cloud-Infrastructure",
			enabled: false,
		})
		updateRule.mockResolvedValueOnce(toggled)
		const body = { enabled: false, previouslyUpdatedAt: PREVIOUS }

		const result = await run(
			makeEvent({ ruleId: CLOUDTRAIL_TAMPERING_RULE_ID, body }),
		)

		expect(result.statusCode).toBe(200)
		expect(updateRule).toHaveBeenCalledWith(CLOUDTRAIL_TAMPERING_RULE_ID, body)
		expect(JSON.parse(result.body)).toEqual({ rule: toggled })
	})

	it("accepts a base64-encoded body", async () => {
		const result = await run(makeEvent({ body: validBody, base64: true }))

		expect(result.statusCode).toBe(200)
		expect(updateRule).toHaveBeenCalledWith(RULE, validBody)
	})

	it("does not read the rule list", async () => {
		await run(makeEvent({ body: validBody }))
		expect(getRules).not.toHaveBeenCalled()
	})
})

describe("PATCH /api/detection-rules/{ruleId}: routing and rule ID", () => {
	it("returns 404 for an unknown rule without parsing or updating", async () => {
		const result = await run(
			makeEvent({ ruleId: "NOT-A-RULE", body: validBody }),
		)

		expect(result.statusCode).toBe(404)
		expect(JSON.parse(result.body)).toEqual({
			message: "The given Rule ID does not exist",
		})
		expect(updateRule).not.toHaveBeenCalled()
	})

	it("checks the rule before the body, so a bad body on an unknown rule is a 404", async () => {
		const result = await run(
			makeEvent({ ruleId: "NOT-A-RULE", body: "{not json" }),
		)

		expect(result.statusCode).toBe(404)
	})

	it("returns 400 when the rule ID path parameter is missing", async () => {
		const result = await run(makeEvent({ ruleId: null, body: validBody }))

		expect(result.statusCode).toBe(400)
		expect(JSON.parse(result.body).message).toBe(
			"Missing rule ID in the route params",
		)
		expect(updateRule).not.toHaveBeenCalled()
	})

	it.each(["PUT /api/detection-rules/{ruleId}", "POST /api/detection-rules/{ruleId}", "DELETE /api/detection-rules/{ruleId}", "GET /api/detection-rules/{ruleId}"])(
		"does not update the rule on the unknown route %s",
		async (routeKey) => {
			const result = await run(makeEvent({ routeKey, body: validBody }))

			expect(result.statusCode).toBe(404)
			expect(JSON.parse(result.body)).toEqual({ message: "Route not found" })
			expect(updateRule).not.toHaveBeenCalled()
		},
	)

	it("does not turn PATCH /rules (no rule ID) into an update", async () => {
		const result = await run(
			makeEvent({ routeKey: "PATCH /api/detection-rules", body: validBody }),
		)

		expect(result.statusCode).toBe(404)
		expect(updateRule).not.toHaveBeenCalled()
	})
})

describe("PATCH /api/detection-rules/{ruleId}: request body validation", () => {
	it.each([
		["a missing body", undefined, "Request body is required"],
		["an empty body", "", "Request body is required"],
		["malformed JSON", "{not json", "Request body must be valid JSON"],
	])("returns 400 for %s", async (_label, body, message) => {
		const result = await run(makeEvent({ body }))

		expect(result.statusCode).toBe(400)
		expect(JSON.parse(result.body).message).toBe(message)
		expect(updateRule).not.toHaveBeenCalled()
	})

	it("returns 400 for invalid base64-wrapped JSON", async () => {
		const result = await run(makeEvent({ body: "{not json", base64: true }))

		expect(result.statusCode).toBe(400)
	})

	it("returns 400 with validation issues for an invalid update", async () => {
		const result = await run(
			makeEvent({ body: { threshold: 0, previouslyUpdatedAt: PREVIOUS } }),
		)

		expect(result.statusCode).toBe(400)
		const body = JSON.parse(result.body)
		expect(body.message).toBe("Invalid request")
		expect(body.issues).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ path: ["threshold"] }),
			]),
		)
		expect(updateRule).not.toHaveBeenCalled()
	})

	it("returns 400 when no editable field is provided", async () => {
		const result = await run(
			makeEvent({ body: { previouslyUpdatedAt: PREVIOUS } }),
		)

		expect(result.statusCode).toBe(400)
		expect(JSON.parse(result.body).issues[0].message).toBe(
			"At least one editable field must be provided",
		)
	})

	it("returns 400 when previouslyUpdatedAt is missing", async () => {
		const result = await run(makeEvent({ body: { threshold: 10 } }))

		expect(result.statusCode).toBe(400)
		expect(updateRule).not.toHaveBeenCalled()
	})

	it("returns 400 when the body tries to change a non-editable field", async () => {
		const result = await run(
			makeEvent({
				body: { ...validBody, ruleId: "AUTH-PASSWORD-SPRAYING-001" },
			}),
		)

		expect(result.statusCode).toBe(400)
		expect(updateRule).not.toHaveBeenCalled()
	})

	it.each([[null], [[]], ["text"], [42]])(
		"returns 400 for a non-object JSON body (%j)",
		async (body) => {
			const result = await run(makeEvent({ body: JSON.stringify(body) }))

			expect(result.statusCode).toBe(400)
			expect(updateRule).not.toHaveBeenCalled()
		},
	)
})

describe("PATCH /api/detection-rules/{ruleId}: repository errors", () => {
	it("returns 409 when the rule changed since it was read", async () => {
		updateRule.mockRejectedValue(
			new RuleUpdateConflictError("Rule changed; reload before retrying"),
		)

		const result = await run(makeEvent({ body: validBody }))

		expect(result.statusCode).toBe(409)
		expect(JSON.parse(result.body)).toEqual({
			message: "Rule changed; reload before retrying",
		})
	})

	it("returns 404 when the repository reports the rule as not found", async () => {
		updateRule.mockRejectedValue(new RuleNotFoundError("Unknown detection rule"))

		const result = await run(makeEvent({ body: validBody }))

		expect(result.statusCode).toBe(404)
		expect(JSON.parse(result.body)).toEqual({
			message: "Unknown detection rule",
		})
	})

	it("returns a generic 500 and logs the error for anything else", async () => {
		const error = new Error("DynamoDB unavailable: table secret-table")
		updateRule.mockRejectedValue(error)

		const result = await run(makeEvent({ body: validBody }))

		expect(result.statusCode).toBe(500)
		expect(JSON.parse(result.body)).toEqual({
			message: "Internal server error",
		})
		expect(result.body).not.toContain("secret-table")
		expect(console.error).toHaveBeenCalledWith({
			detail: "Unhandled error",
			error,
		})
	})

	it("returns 500 for a non-Error rejection", async () => {
		updateRule.mockRejectedValue("boom")

		const result = await run(makeEvent({ body: validBody }))

		expect(result.statusCode).toBe(500)
	})
})
