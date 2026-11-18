import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const { send } = vi.hoisted(() => ({ send: vi.fn() }))

vi.mock("@aws-sdk/lib-dynamodb", async (importActual) => ({
	...(await importActual<typeof import("@aws-sdk/lib-dynamodb")>()),
	DynamoDBDocumentClient: { from: () => ({ send }) },
}))

import { detectionRuleEvaluationRegistry } from "../../src/detection-rules/evalutationRegistry"
import {
	clearDetectionRulesCache,
	fetchDetectionRules,
} from "../../src/services/fetchDetectionRulesService"

const TABLE = "test-detection-rules"

const REGISTERED_IDS = detectionRuleEvaluationRegistry.map((rule) => rule.id)
const [FIRST_ID, SECOND_ID] = REGISTERED_IDS
const TAMPERING_ID = "CLOUD-TRAIL-TAMPERING-001"
const AUTH_IDS = REGISTERED_IDS.filter((id) => id.startsWith("AUTH-"))

const config = (ruleId: string, o: Record<string, unknown> = {}) => ({
	ruleId,
	enabled: true,
	category: "Authentication",
	label: "Test rule",
	threshold: 5,
	windowSeconds: 300,
	severity: "high",
	updatedAt: "2026-01-01T00:00:00.000Z",
	...o,
})

/** One valid config row per registered rule; `overrides` patches specific rules. */
const allConfigs = (overrides: Record<string, Record<string, unknown>> = {}) =>
	REGISTERED_IDS.map((id) => config(id, overrides[id]))

beforeEach(() => {
	send.mockReset()
	vi.stubEnv("DETECTION_RULES_TABLE_NAME", TABLE)
	vi.useFakeTimers()
	// The cache is module-level state shared across tests.
	clearDetectionRulesCache()
})

afterEach(() => {
	vi.useRealTimers()
	vi.unstubAllEnvs()
})

describe("fetchDetectionRules: rule-specific configuration", () => {
	describe.each(AUTH_IDS)("%s", (id) => {
		it.each([
			["missing threshold", { threshold: undefined }],
			["missing windowSeconds", { windowSeconds: undefined }],
		])("fails when enabled with %s", async (_label, override) => {
			send.mockResolvedValue({ Items: allConfigs({ [id]: override }) })

			await expect(fetchDetectionRules()).rejects.toThrow(
				`Invalid configuration for detection rule: ${id}`,
			)
		})

		it("does not fail when the invalid rule is disabled", async () => {
			send.mockResolvedValue({
				Items: allConfigs({
					[id]: { enabled: false, threshold: undefined, windowSeconds: undefined },
				}),
			})

			await expect(fetchDetectionRules()).resolves.toBeDefined()
		})
	})

	it("ignores threshold and window values on the CloudTrail rule", async () => {
		send.mockResolvedValue({
			Items: allConfigs({ [TAMPERING_ID]: { threshold: 1, windowSeconds: 1 } }),
		})

		await expect(fetchDetectionRules()).resolves.toBeDefined()
	})
})

describe("fetchDetectionRules: fetching", () => {
	it("scans the configured table with a consistent read", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		await fetchDetectionRules()

		expect(send).toHaveBeenCalledOnce()
		const input = send.mock.calls[0][0].input
		expect(input).toMatchObject({ TableName: TABLE, ConsistentRead: true })
	})

	it("pairs every registered rule with its own configuration, in registry order", async () => {
		// Rows come back from DynamoDB in arbitrary order
		send.mockResolvedValue({ Items: [...allConfigs()].reverse() })

		const result = await fetchDetectionRules()

		expect(result.map(({ detectionRule }) => detectionRule.id)).toEqual(
			REGISTERED_IDS,
		)
		for (const { detectionRule, configuration } of result) {
			expect(configuration.ruleId).toBe(detectionRule.id)
		}
	})

	it("includes both authentication and cloudtrail rules", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		const result = await fetchDetectionRules()
		const eventTypes = new Set(
			result.map(({ detectionRule }) => detectionRule.eventType),
		)

		expect(eventTypes).toEqual(new Set(["authentication", "cloudtrail"]))
	})

	it("ignores table rows that are not registered rules", async () => {
		send.mockResolvedValue({ Items: [...allConfigs(), config("NOT-A-RULE")] })

		const result = await fetchDetectionRules()

		expect(result).toHaveLength(REGISTERED_IDS.length)
	})

	it("throws when a registered rule has no configuration row", async () => {
		send.mockResolvedValue({ Items: [] })

		await expect(fetchDetectionRules()).rejects.toThrow(
			`Missing configuration for detection rule: ${FIRST_ID}`,
		)

		clearDetectionRulesCache()
		send.mockResolvedValue({})
		await expect(fetchDetectionRules()).rejects.toThrow(
			"Missing configuration for detection rule",
		)
	})

	it("names the rule whose row is missing", async () => {
		const missing = REGISTERED_IDS[REGISTERED_IDS.length - 1]
		send.mockResolvedValue({
			Items: allConfigs().filter((item) => item.ruleId !== missing),
		})

		await expect(fetchDetectionRules()).rejects.toThrow(missing)
	})

	it("throws without calling DynamoDB when the table name is not configured", async () => {
		vi.stubEnv("DETECTION_RULES_TABLE_NAME", "")

		await expect(fetchDetectionRules()).rejects.toThrow(
			"DETECTION_RULES_TABLE_NAME env var is missing",
		)
		expect(send).not.toHaveBeenCalled()
	})

	it("propagates DynamoDB errors", async () => {
		send.mockRejectedValue(new Error("DynamoDB unavailable"))

		await expect(fetchDetectionRules()).rejects.toThrow("DynamoDB unavailable")
	})
})

describe("fetchDetectionRules: enabled / disabled", () => {
	it("skips a disabled rule instead of treating it as missing", async () => {
		send.mockResolvedValue({
			Items: allConfigs({ [FIRST_ID]: { enabled: false } }),
		})

		const result = await fetchDetectionRules()

		expect(result.map(({ detectionRule }) => detectionRule.id)).toEqual(
			REGISTERED_IDS.filter((id) => id !== FIRST_ID),
		)
	})

	it("returns an empty list when every rule is disabled", async () => {
		send.mockResolvedValue({
			Items: allConfigs(
				Object.fromEntries(REGISTERED_IDS.map((id) => [id, { enabled: false }])),
			),
		})

		await expect(fetchDetectionRules()).resolves.toEqual([])
	})

	it("returns the stored configuration for enabled rules", async () => {
		const item = config(SECOND_ID, {
			threshold: 9,
			windowSeconds: 60,
			severity: "critical",
		})
		send.mockResolvedValue({
			Items: allConfigs().map((c) => (c.ruleId === SECOND_ID ? item : c)),
		})

		const result = await fetchDetectionRules()
		const entry = result.find(({ detectionRule }) => detectionRule.id === SECOND_ID)

		expect(entry?.configuration).toEqual(item)
	})
})

describe("fetchDetectionRules: validation", () => {
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
			Items: allConfigs({ [FIRST_ID]: override }),
		})

		await expect(fetchDetectionRules()).rejects.toThrow()
	})

	it.each(["category", "label", "severity"])(
		"rejects a config with a missing %s",
		async (field) => {
			const { [field]: _omit, ...incomplete } = config(FIRST_ID) as Record<
				string,
				unknown
			>
			send.mockResolvedValue({
				Items: [incomplete, ...allConfigs().slice(1)],
			})

			await expect(fetchDetectionRules()).rejects.toThrow()
		},
	)

	it("accepts a CloudTrail rule config without threshold or windowSeconds", async () => {
		const { threshold: _t, windowSeconds: _w, ...noTuning } = config(
			TAMPERING_ID,
		)
		send.mockResolvedValue({
			Items: [
				...allConfigs({ [TAMPERING_ID]: {} }).filter(
					(c) => c.ruleId !== TAMPERING_ID,
				),
				noTuning,
			],
		})

		await expect(fetchDetectionRules()).resolves.toBeDefined()
	})

	it("rejects the whole scan if any single item is invalid", async () => {
		send.mockResolvedValue({
			Items: [...allConfigs(), config("OTHER", { threshold: 0 })],
		})

		await expect(fetchDetectionRules()).rejects.toThrow()
	})
})

describe("fetchDetectionRules: caching", () => {
	it("serves repeat calls from cache and still returns the rules", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		const first = await fetchDetectionRules()
		const second = await fetchDetectionRules()

		expect(send).toHaveBeenCalledOnce()
		// Regression: a warm cache used to return undefined
		expect(second).toHaveLength(REGISTERED_IDS.length)
		expect(second).toEqual(first)
	})

	it("expires the cache after 60 seconds", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		await fetchDetectionRules()
		await vi.advanceTimersByTimeAsync(59_999)
		await fetchDetectionRules()
		expect(send).toHaveBeenCalledTimes(1)

		await vi.advanceTimersByTimeAsync(1)
		await fetchDetectionRules()
		expect(send).toHaveBeenCalledTimes(2)
	})

	it("picks up changed configuration after the cache expires", async () => {
		const thresholdOf = (
			result: Awaited<ReturnType<typeof fetchDetectionRules>>,
		) =>
			result.find(({ detectionRule }) => detectionRule.id === FIRST_ID)
				?.configuration.threshold

		send.mockResolvedValueOnce({
			Items: allConfigs({ [FIRST_ID]: { threshold: 5 } }),
		})
		const before = await fetchDetectionRules()

		await vi.advanceTimersByTimeAsync(60_000)
		send.mockResolvedValueOnce({
			Items: allConfigs({ [FIRST_ID]: { threshold: 10 } }),
		})
		const after = await fetchDetectionRules()

		expect(thresholdOf(before)).toBe(5)
		expect(thresholdOf(after)).toBe(10)
	})

	it("does not serve stale configuration before the cache expires", async () => {
		send.mockResolvedValueOnce({
			Items: allConfigs({ [FIRST_ID]: { threshold: 5 } }),
		})
		await fetchDetectionRules()

		await vi.advanceTimersByTimeAsync(30_000)
		send.mockResolvedValueOnce({
			Items: allConfigs({ [FIRST_ID]: { threshold: 10 } }),
		})
		const during = await fetchDetectionRules()

		expect(during[0].configuration.threshold).toBe(5)
		expect(send).toHaveBeenCalledTimes(1)
	})

	it("applies a disabled flag from the cached configuration", async () => {
		send.mockResolvedValue({
			Items: allConfigs({ [FIRST_ID]: { enabled: false } }),
		})

		await fetchDetectionRules()
		const cached = await fetchDetectionRules()

		expect(send).toHaveBeenCalledOnce()
		expect(cached.map(({ detectionRule }) => detectionRule.id)).not.toContain(
			FIRST_ID,
		)
	})

	it("does not cache after a validation failure", async () => {
		send.mockResolvedValueOnce({
			Items: allConfigs({ [FIRST_ID]: { threshold: 0 } }),
		})
		await expect(fetchDetectionRules()).rejects.toThrow()

		send.mockResolvedValueOnce({ Items: allConfigs() })
		await expect(fetchDetectionRules()).resolves.toHaveLength(
			REGISTERED_IDS.length,
		)
		expect(send).toHaveBeenCalledTimes(2)
	})

	it("does not cache after a DynamoDB error", async () => {
		send.mockRejectedValueOnce(new Error("DynamoDB unavailable"))
		await expect(fetchDetectionRules()).rejects.toThrow()

		send.mockResolvedValueOnce({ Items: allConfigs() })
		await expect(fetchDetectionRules()).resolves.toHaveLength(
			REGISTERED_IDS.length,
		)
		expect(send).toHaveBeenCalledTimes(2)
	})

	it("clearDetectionRulesCache forces the next call to refetch", async () => {
		send.mockResolvedValue({ Items: allConfigs() })

		await fetchDetectionRules()
		clearDetectionRulesCache()
		await fetchDetectionRules()

		expect(send).toHaveBeenCalledTimes(2)
	})
})
