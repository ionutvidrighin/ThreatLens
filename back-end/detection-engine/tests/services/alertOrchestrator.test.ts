import { beforeEach, describe, expect, it, vi } from "vitest"
import { EVENT_DUPLICATE, EVENT_STORED } from "../../src/constants"
import { storeSecurityAlert } from "../../src/repositories/securityAlerts"
import { orchestrateAlert } from "../../src/services/alertOrchestrator"
import type { DetectionFinding } from "../../src/types"
import {
	ATTACKER_IP,
	BRUTE_FORCE_RULE_ID,
	BUCKET_START,
	PASSWORD_SPRAYING_RULE_ID,
} from "../helpers"

vi.mock("../../src/repositories/securityAlerts", () => ({
	storeSecurityAlert: vi.fn(),
}))

const store = vi.mocked(storeSecurityAlert)

const finding = (o: Partial<DetectionFinding> = {}): DetectionFinding => ({
	ruleId: BRUTE_FORCE_RULE_ID,
	ruleName: "Test rule",
	severity: "high",
	sourceIp: ATTACKER_IP,
	eventTime: BUCKET_START + 10_000,
	windowSeconds: 300,
	description: "desc",
	metadata: { failedAttempts: 5 },
	...o,
})

beforeEach(() => {
	store.mockReset()
	store.mockResolvedValue(EVENT_STORED)
})

describe("orchestrateAlert", () => {
	it("persists a well-formed alert and reports it as created", async () => {
		const f = finding()
		const result = await orchestrateAlert(f)

		expect(result).toEqual({
			created: true,
			alertId: expect.stringMatching(/^alert-[0-9a-f]{24}$/),
			ruleId: f.ruleId,
			sourceIp: f.sourceIp,
		})
		expect(store).toHaveBeenCalledOnce()
		expect(store.mock.calls[0][0]).toMatchObject({
			alertId: result.alertId,
			entityType: "ALERT",
			ruleId: f.ruleId,
			ruleName: "Test rule",
			severity: "high",
			status: "open",
			sourceIp: f.sourceIp,
			description: "desc",
			windowStart: new Date(f.eventTime - 300_000).toISOString(),
			windowEnd: new Date(f.eventTime).toISOString(),
			failedAttempts: 5,
		})
		expect(Number.isNaN(Date.parse(store.mock.calls[0][0].createdAt))).toBe(
			false,
		)
	})

	it("spreads rule metadata onto the alert", async () => {
		await orchestrateAlert(
			finding({
				ruleId: PASSWORD_SPRAYING_RULE_ID,
				metadata: { targetedAccounts: 5, usernames: ["a", "b"] },
			}),
		)

		expect(store.mock.calls[0][0]).toMatchObject({
			targetedAccounts: 5,
			usernames: ["a", "b"],
		})
		expect(store.mock.calls[0][0]).not.toHaveProperty("failedAttempts")
	})

	it("clamps windowStart to the epoch for very early events", async () => {
		await orchestrateAlert(finding({ eventTime: 1000 }))
		expect(store.mock.calls[0][0].windowStart).toBe("1970-01-01T00:00:00.000Z")
	})

	it("reports created: false when the alert already exists (deduplication)", async () => {
		store.mockResolvedValue(EVENT_DUPLICATE)
		const result = await orchestrateAlert(finding())

		expect(result.created).toBe(false)
		expect(result.alertId).toBeDefined()
	})

	it("derives the same alertId for the same rule, IP and time bucket", async () => {
		const a = await orchestrateAlert(finding({ eventTime: BUCKET_START + 1 }))
		const b = await orchestrateAlert(
			finding({ eventTime: BUCKET_START + 299_999 }),
		)
		expect(a.alertId).toBe(b.alertId)
	})

	it("derives different alertIds across buckets, IPs and rules", async () => {
		const base = await orchestrateAlert(finding())
		const nextBucket = await orchestrateAlert(
			finding({ eventTime: BUCKET_START + 300_000 }),
		)
		const otherIp = await orchestrateAlert(finding({ sourceIp: "198.51.100.7" }))
		const otherRule = await orchestrateAlert(
			finding({ ruleId: PASSWORD_SPRAYING_RULE_ID }),
		)

		const ids = [base, nextBucket, otherIp, otherRule].map((r) => r.alertId)
		expect(new Set(ids).size).toBe(4)
	})

	it("honours the finding's own window length when bucketing", async () => {
		const a = await orchestrateAlert(
			finding({ windowSeconds: 60, eventTime: BUCKET_START }),
		)
		const b = await orchestrateAlert(
			finding({ windowSeconds: 60, eventTime: BUCKET_START + 60_000 }),
		)
		expect(a.alertId).not.toBe(b.alertId)
	})

	it("propagates storage failures", async () => {
		store.mockRejectedValue(new Error("DynamoDB unavailable"))
		await expect(orchestrateAlert(finding())).rejects.toThrow(
			"DynamoDB unavailable",
		)
	})
})

describe("orchestrateAlert: actor", () => {
	it("stores the actor on the alert when the finding has one", async () => {
		await orchestrateAlert(finding({ actor: "AccountFullAccessRole" }))

		expect(store.mock.calls[0][0]).toMatchObject({
			actor: "AccountFullAccessRole",
		})
	})

	it("omits the actor field when the finding has none", async () => {
		await orchestrateAlert(finding())

		expect(store.mock.calls[0][0]).not.toHaveProperty("actor")
	})

	it("identifies the alert by actor, not by a shared placeholder IP", async () => {
		const a = await orchestrateAlert(
			finding({ sourceIp: "unknown", actor: "alice-role" }),
		)
		const b = await orchestrateAlert(
			finding({ sourceIp: "unknown", actor: "bob-role" }),
		)

		expect(a.alertId).not.toBe(b.alertId)
	})

	it("deduplicates repeats by the same actor within a bucket", async () => {
		const a = await orchestrateAlert(
			finding({ sourceIp: "1.1.1.1", actor: "alice-role" }),
		)
		// Same actor from a different IP, same rule and bucket: same alert
		const b = await orchestrateAlert(
			finding({ sourceIp: "2.2.2.2", actor: "alice-role" }),
		)

		expect(a.alertId).toBe(b.alertId)
	})

	it("keeps IP-based alert IDs unchanged when there is no actor", async () => {
		const withoutActor = await orchestrateAlert(finding())
		const sameIpOtherActor = await orchestrateAlert(
			finding({ actor: "alice-role" }),
		)

		expect(withoutActor.alertId).not.toBe(sameIpOtherActor.alertId)
	})
})

describe("orchestrateAlert: stateless findings (no window)", () => {
	const stateless = (o: Partial<DetectionFinding> = {}) =>
		finding({ windowSeconds: 0, eventId: "evt-1", actor: "alice-role", ...o })

	it("gives different alerts to different events by the same actor", async () => {
		const a = await orchestrateAlert(stateless({ eventId: "evt-1" }))
		const b = await orchestrateAlert(stateless({ eventId: "evt-2" }))

		expect(a.alertId).not.toBe(b.alertId)
	})

	it("derives the same alertId when the same event is delivered again", async () => {
		const a = await orchestrateAlert(stateless())
		const b = await orchestrateAlert(stateless())

		expect(a.alertId).toBe(b.alertId)
	})

	it("never produces a NaN-based id", async () => {
		const a = await orchestrateAlert(stateless({ eventTime: BUCKET_START }))
		const b = await orchestrateAlert(
			stateless({ eventTime: BUCKET_START + 1000, eventId: "evt-2" }),
		)

		expect(a.alertId).not.toBe(b.alertId)
	})

	it("stores a zero-length window ending at the event time", async () => {
		const f = stateless()
		await orchestrateAlert(f)

		expect(store.mock.calls[0][0]).toMatchObject({
			windowStart: new Date(f.eventTime).toISOString(),
			windowEnd: new Date(f.eventTime).toISOString(),
		})
	})

	it("refuses a finding with neither a window nor an eventId", async () => {
		await expect(
			orchestrateAlert(stateless({ eventId: undefined })),
		).rejects.toThrow("needs a window or an eventId")
		expect(store).not.toHaveBeenCalled()
	})

	it("ignores eventId for windowed findings (still one alert per bucket)", async () => {
		const a = await orchestrateAlert(finding({ eventId: "evt-1" }))
		const b = await orchestrateAlert(finding({ eventId: "evt-2" }))

		expect(a.alertId).toBe(b.alertId)
	})
})
