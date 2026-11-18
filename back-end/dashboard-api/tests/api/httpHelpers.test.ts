import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { afterEach, describe, expect, it, vi } from "vitest"
import { z } from "zod"
import {
	errorToResponse,
	jsonResponse,
	parseJsonBody,
	parseOrThrow400,
} from "@/api/httpHelpers"
import {
	ConflictError,
	HttpError,
	NotFoundError,
	RuleNotFoundError,
	RuleUpdateConflictError,
} from "@/errors"

const eventWith = (fields: Partial<APIGatewayProxyEventV2>) =>
	fields as APIGatewayProxyEventV2

const bodyOf = (response: { body?: string }) => JSON.parse(response.body ?? "")

// Returns what the function threw, so assertions can inspect the error object.
const catchError = (fn: () => unknown) => {
	try {
		fn()
	} catch (error) {
		return error
	}
	throw new Error("Expected the function to throw")
}

afterEach(() => {
	vi.restoreAllMocks()
})

describe("jsonResponse", () => {
	it("returns the status code, a JSON content type and a stringified body", () => {
		const response = jsonResponse({ statusCode: 200, body: { ok: true } })

		expect(response).toEqual({
			statusCode: 200,
			headers: { "Content-Type": "application/json" },
			body: '{"ok":true}',
		})
	})
})

describe("parseJsonBody", () => {
	it("parses a plain JSON body", () => {
		const event = eventWith({ body: '{"threshold":8}', isBase64Encoded: false })

		expect(parseJsonBody(event)).toEqual({ threshold: 8 })
	})

	it("decodes a base64 body before parsing", () => {
		const event = eventWith({
			body: Buffer.from('{"threshold":8}').toString("base64"),
			isBase64Encoded: true,
		})

		expect(parseJsonBody(event)).toEqual({ threshold: 8 })
	})

	it("throws a 400 HttpError when the body is missing", () => {
		const error = catchError(() =>
			parseJsonBody(eventWith({ isBase64Encoded: false })),
		)

		expect(error).toBeInstanceOf(HttpError)
		expect(error).toMatchObject({
			statusCode: 400,
			message: "Request body is required",
		})
	})

	it("throws a 400 HttpError when the body is not valid JSON", () => {
		const error = catchError(() =>
			parseJsonBody(eventWith({ body: "{broken", isBase64Encoded: false })),
		)

		expect(error).toBeInstanceOf(HttpError)
		expect(error).toMatchObject({
			statusCode: 400,
			message: "Request body must be valid JSON",
		})
	})
})

describe("parseOrThrow400", () => {
	const schema = z.object({ threshold: z.number().int().min(1) }).strict()

	it("returns the validated data", () => {
		expect(parseOrThrow400(schema, { threshold: 5 })).toEqual({ threshold: 5 })
	})

	it("throws a 400 HttpError carrying the Zod issues", () => {
		const error = catchError(() => parseOrThrow400(schema, { threshold: 0 }))

		expect(error).toBeInstanceOf(HttpError)
		expect(error).toMatchObject({ statusCode: 400, message: "Invalid request" })
		expect((error as HttpError).details).toEqual(
			expect.arrayContaining([expect.objectContaining({ path: ["threshold"] })]),
		)
	})

	it("rejects unknown keys when the schema is strict", () => {
		const error = catchError(() =>
			parseOrThrow400(schema, { threshold: 5, extra: true }),
		)

		expect(error).toBeInstanceOf(HttpError)
	})
})

describe("errorToResponse", () => {
	it("uses the HttpError status code and includes its details as issues", () => {
		const response = errorToResponse(
			new HttpError(400, "Invalid request", [{ path: ["threshold"] }]),
		)

		expect(response.statusCode).toBe(400)
		expect(bodyOf(response as { body?: string })).toEqual({
			message: "Invalid request",
			issues: [{ path: ["threshold"] }],
		})
	})

	it("omits issues when the HttpError has no details", () => {
		const response = errorToResponse(new HttpError(400, "Nope"))

		expect(bodyOf(response as { body?: string })).toEqual({ message: "Nope" })
	})

	it.each([
		["NotFoundError", new NotFoundError("missing")],
		["RuleNotFoundError", new RuleNotFoundError("missing")],
	])("maps %s to 404", (_name, error) => {
		const response = errorToResponse(error)

		expect(response.statusCode).toBe(404)
		expect(bodyOf(response as { body?: string })).toEqual({
			message: "missing",
		})
	})

	it.each([
		["ConflictError", new ConflictError("stale")],
		["RuleUpdateConflictError", new RuleUpdateConflictError("stale")],
	])("maps %s to 409", (_name, error) => {
		const response = errorToResponse(error)

		expect(response.statusCode).toBe(409)
		expect(bodyOf(response as { body?: string })).toEqual({
			message: "stale",
		})
	})

	it("returns a generic 500 for unexpected errors and does not leak the message", () => {
		const logSpy = vi.spyOn(console, "error").mockImplementation(() => {})

		const response = errorToResponse(new Error("table arn:aws:dynamodb:secret"))

		expect(response.statusCode).toBe(500)
		expect(bodyOf(response as { body?: string })).toEqual({
			message: "Internal server error",
		})
		expect(logSpy).toHaveBeenCalledTimes(1)
	})

	it("returns a generic 500 for non-Error values", () => {
		vi.spyOn(console, "error").mockImplementation(() => {})

		expect(errorToResponse("a string was thrown").statusCode).toBe(500)
	})

	it("returns a 500 for a ZodError that escapes (e.g. corrupted stored data)", () => {
		vi.spyOn(console, "error").mockImplementation(() => {})
		const zodError = z.number().safeParse("x").error

		expect(errorToResponse(zodError).statusCode).toBe(500)
	})
})
