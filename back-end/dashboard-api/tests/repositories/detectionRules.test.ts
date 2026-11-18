import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const { send } = vi.hoisted(() => ({ send: vi.fn() }))

// Only the pieces the repository uses are mocked. ScanCommand is a minimal
// stand-in that exposes its input, which is all the tests inspect.
vi.mock("@aws-sdk/lib-dynamodb", () => ({
	DynamoDBDocumentClient: { from: () => ({ send }) },
	ScanCommand: class {
		constructor(public input: unknown) {}
	},
	UpdateCommand: class {
		constructor(public input: unknown) {}
	},
}))

import { getDetectionRules } from "@/repositories/detectionRules"
import { DETECTION_RULE_IDS } from "@/repositories/utils/detectionRulesHelpers"
import {
	BRUTE_FORCE_RULE_ID,
	CLOUDTRAIL_TAMPERING_RULE_ID,
	PASSWORD_SPRAYING_RULE_ID,
	ruleConfig,
} from "../fixtures"

const TABLE = "test-detection-rules"

const allConfigs = () => DETECTION_RULE_IDS.map((id) => ruleConfig(id))

beforeEach(() => {
	send.mockReset()
	vi.stubEnv("DETECTION_RULES_TABLE_NAME", TABLE)
})

afterEach(() => {
	vi.unstubAllEnvs()
})

describe("getDetectionRules: configuration", () => {
	it("throws when DETECTION_RULES_TABLE_NAME is missing", async () => {
		vi.stubEnv("DETECTION_RULES_TABLE_NAME", "")

		await expect(getDetectionRules()).rejects.toThrow(
			"DETECTION_RULES_TABLE_NAME env var is missing",
		)
		expect(send).not.toHaveBeenCalled()
	})

	it("reads the table name at call time", async () => {
		vi.stubEnv("DETECTION_RULES_TABLE_NAME", "other-table")
		send.mockResolvedValue({ Items: allConfigs() })

		await getDetectionRules()

		expect(send.mock.calls[0][0].input.TableName).toBe("other-table")
	})
})

describe("getDetectionRules: fetching", () => {
	it("scans the whole table with a consistent read", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		await getDetectionRules()

		expect(send).toHaveBeenCalledOnce()
		expect(send.mock.calls[0][0].input).toEqual({
			TableName: TABLE,
			ConsistentRead: true,
		})
	})

	it("returns the validated configs, including category and label", async () => {
		const items = [
			ruleConfig(BRUTE_FORCE_RULE_ID, {
				threshold: 9,
				severity: "critical",
				label: "Brute force",
			}),
			ruleConfig(PASSWORD_SPRAYING_RULE_ID, {
				enabled: false,
				windowSeconds: 60,
			}),
			ruleConfig(CLOUDTRAIL_TAMPERING_RULE_ID, {
				category: "Cloud-Infrastructure",
				label: "CloudTrail tampering",
			}),
		]
		send.mockResolvedValue({ Items: items })

		await expect(getDetectionRules()).resolves.toEqual(items)
	})

	it("returns an empty list when the table has no items", async () => {
		send.mockResolvedValue({ Items: [] })
		await expect(getDetectionRules()).resolves.toEqual([])

		send.mockResolvedValue({})
		await expect(getDetectionRules()).resolves.toEqual([])
	})

	it("returns whatever is in the table, without checking known rule IDs", async () => {
		send.mockResolvedValue({
			Items: [ruleConfig(BRUTE_FORCE_RULE_ID), ruleConfig("EXTRA-001")],
		})

		const result = await getDetectionRules()

		expect(result.map((c) => c.ruleId)).toEqual([
			BRUTE_FORCE_RULE_ID,
			"EXTRA-001",
		])
	})

	it("does not cache: every call queries DynamoDB again", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		await getDetectionRules()
		await getDetectionRules()

		expect(send).toHaveBeenCalledTimes(2)
	})

	it("propagates DynamoDB errors", async () => {
		send.mockRejectedValue(new Error("DynamoDB unavailable"))

		await expect(getDetectionRules()).rejects.toThrow("DynamoDB unavailable")
	})
})

describe("getDetectionRules: validation", () => {
	it.each([
		["threshold below 1", { threshold: 0 }],
		["non-integer threshold", { threshold: 2.5 }],
		["window below 1", { windowSeconds: 0 }],
		["window above 24h", { windowSeconds: 86401 }],
		["unknown severity", { severity: "urgent" }],
		["non-boolean enabled", { enabled: "true" }],
		["invalid updatedAt", { updatedAt: "yesterday" }],
		["empty ruleId", { ruleId: "" }],
		["empty category", { category: "" }],
		["empty label", { label: "" }],
	])("rejects a config with %s", async (_label, override) => {
		send.mockResolvedValue({
			Items: [
				ruleConfig(BRUTE_FORCE_RULE_ID, override),
				ruleConfig(PASSWORD_SPRAYING_RULE_ID),
			],
		})

		await expect(getDetectionRules()).rejects.toThrow()
	})

	it("accepts a config without threshold or windowSeconds (e.g. CloudTrail tampering)", async () => {
		const { threshold: _t, windowSeconds: _w, ...noTuning } = ruleConfig(
			CLOUDTRAIL_TAMPERING_RULE_ID,
			{ category: "Cloud-Infrastructure" },
		)
		send.mockResolvedValue({ Items: [noTuning] })

		await expect(getDetectionRules()).resolves.toEqual([noTuning])
	})

	it.each(["category", "label"])(
		"rejects a config with a missing %s",
		async (field) => {
			const { [field]: _omit, ...incomplete } = ruleConfig(
				BRUTE_FORCE_RULE_ID,
			) as Record<string, unknown>
			send.mockResolvedValue({
				Items: [incomplete, ruleConfig(PASSWORD_SPRAYING_RULE_ID)],
			})

			await expect(getDetectionRules()).rejects.toThrow()
		},
	)

	it("rejects the whole result if any single item is invalid", async () => {
		send.mockResolvedValue({
			Items: [
				ruleConfig(BRUTE_FORCE_RULE_ID),
				ruleConfig(PASSWORD_SPRAYING_RULE_ID, { threshold: 0 }),
			],
		})

		await expect(getDetectionRules()).rejects.toThrow()
	})

	it("accepts the boundary values (threshold 1, window 1 and 86400)", async () => {
		send.mockResolvedValue({
			Items: [
				ruleConfig(BRUTE_FORCE_RULE_ID, { threshold: 1, windowSeconds: 1 }),
				ruleConfig(PASSWORD_SPRAYING_RULE_ID, { windowSeconds: 86400 }),
			],
		})

		await expect(getDetectionRules()).resolves.toHaveLength(2)
	})

	it.each(["low", "medium", "high", "critical"])(
		"accepts severity %s",
		async (severity) => {
			send.mockResolvedValue({
				Items: [ruleConfig(BRUTE_FORCE_RULE_ID, { severity })],
			})

			await expect(getDetectionRules()).resolves.toHaveLength(1)
		},
	)
})
