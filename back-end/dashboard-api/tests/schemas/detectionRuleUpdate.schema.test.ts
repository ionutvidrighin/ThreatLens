import { describe, expect, it } from "vitest"
import { DetectionRuleUpdateSchema } from "@/schemas/detectionRuleUpdate.schema"

const PREVIOUS = "2026-01-01T00:00:00.000Z"

const parse = (input: unknown) => DetectionRuleUpdateSchema.safeParse(input)

describe("DetectionRuleUpdateSchema: valid updates", () => {
	it.each([
		["enabled", { enabled: false }],
		["threshold", { threshold: 10 }],
		["windowSeconds", { windowSeconds: 600 }],
		["severity", { severity: "critical" }],
	])("accepts an update of only %s", (_field, change) => {
		const result = parse({ ...change, previouslyUpdatedAt: PREVIOUS })

		expect(result.success).toBe(true)
		expect(result.data).toEqual({ ...change, previouslyUpdatedAt: PREVIOUS })
	})

	it("accepts all editable fields together", () => {
		const input = {
			enabled: true,
			threshold: 3,
			windowSeconds: 120,
			severity: "low",
			previouslyUpdatedAt: PREVIOUS,
		}

		expect(parse(input).data).toEqual(input)
	})

	it("treats enabled: false as a real value, not as absent", () => {
		expect(parse({ enabled: false, previouslyUpdatedAt: PREVIOUS }).success).toBe(
			true,
		)
	})

	it.each(["low", "medium", "high", "critical"])("accepts severity %s", (severity) => {
		expect(parse({ severity, previouslyUpdatedAt: PREVIOUS }).success).toBe(true)
	})

	it("accepts the boundary values (threshold 1, window 1 and 86400)", () => {
		expect(
			parse({ threshold: 1, windowSeconds: 1, previouslyUpdatedAt: PREVIOUS })
				.success,
		).toBe(true)
		expect(
			parse({ windowSeconds: 86400, previouslyUpdatedAt: PREVIOUS }).success,
		).toBe(true)
	})
})

describe("DetectionRuleUpdateSchema: at least one editable field", () => {
	it("rejects a body with only previouslyUpdatedAt", () => {
		const result = parse({ previouslyUpdatedAt: PREVIOUS })

		expect(result.success).toBe(false)
		expect(result.error?.issues[0].message).toBe(
			"At least one editable field must be provided",
		)
	})

	it("rejects editable fields that are explicitly undefined", () => {
		expect(
			parse({
				enabled: undefined,
				threshold: undefined,
				previouslyUpdatedAt: PREVIOUS,
			}).success,
		).toBe(false)
	})

	it("rejects an empty object", () => {
		expect(parse({}).success).toBe(false)
	})
})

describe("DetectionRuleUpdateSchema: previouslyUpdatedAt", () => {
	it("is required", () => {
		const result = parse({ threshold: 5 })

		expect(result.success).toBe(false)
		expect(result.error?.issues.some((i) => i.path[0] === "previouslyUpdatedAt")).toBe(
			true,
		)
	})

	it.each([
		["a non-date string", "yesterday"],
		["a date without a time", "2026-01-01"],
		["a number", 1767225600000],
		["null", null],
		["an empty string", ""],
	])("rejects %s", (_label, value) => {
		expect(parse({ threshold: 5, previouslyUpdatedAt: value }).success).toBe(false)
	})
})

describe("DetectionRuleUpdateSchema: invalid field values", () => {
	it.each([
		["threshold 0", { threshold: 0 }],
		["negative threshold", { threshold: -1 }],
		["fractional threshold", { threshold: 2.5 }],
		["string threshold", { threshold: "5" }],
		["window 0", { windowSeconds: 0 }],
		["window above 24h", { windowSeconds: 86401 }],
		["fractional window", { windowSeconds: 30.5 }],
		["unknown severity", { severity: "urgent" }],
		["uppercase severity", { severity: "HIGH" }],
		["string enabled", { enabled: "true" }],
		["numeric enabled", { enabled: 1 }],
		["null threshold", { threshold: null }],
	])("rejects %s", (_label, change) => {
		expect(parse({ ...change, previouslyUpdatedAt: PREVIOUS }).success).toBe(false)
	})

	it("rejects an invalid field even when another field is valid", () => {
		expect(
			parse({ enabled: true, threshold: 0, previouslyUpdatedAt: PREVIOUS }).success,
		).toBe(false)
	})
})

describe("DetectionRuleUpdateSchema: non-editable fields (strict)", () => {
	it.each([
		["ruleId", { ruleId: "AUTH-BRUTE-FORCE-001" }],
		["updatedAt", { updatedAt: PREVIOUS }],
		["an unknown field", { foo: "bar" }],
	])("rejects %s in the body", (_label, extra) => {
		const result = parse({ threshold: 5, previouslyUpdatedAt: PREVIOUS, ...extra })

		expect(result.success).toBe(false)
		expect(result.error?.issues[0].code).toBe("unrecognized_keys")
	})
})

describe("DetectionRuleUpdateSchema: non-object input", () => {
	it.each([null, undefined, "text", 42, [], true])("rejects %j", (input) => {
		expect(parse(input).success).toBe(false)
	})
})
