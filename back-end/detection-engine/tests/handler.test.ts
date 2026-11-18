import { beforeEach, describe, expect, it, vi } from "vitest"
import {
	EVENT_DUPLICATE,
	EVENT_STORED,
} from "../src/constants"
import { handler } from "../src/handler"
import { clearDetectionRulesCache } from "../src/services/fetchDetectionRulesService"
import type { AuthenticationFailure, SecurityAlert } from "../src/types"
import {
	ATTACKER_IP,
	BRUTE_FORCE_RULE_ID,
	BUCKET_START,
	CLOUDTRAIL_LOG_BUCKET_NAME,
	CLOUDTRAIL_TAMPERING_RULE_ID,
	makeCloudTrailEvent,
	makeConfig,
	makeEvent,
	makeRecord,
	makeSqsEvent,
	PASSWORD_SPRAYING_RULE_ID,
	SUCCESS_AFTER_FAILURES_RULE_ID,
	silenceConsole,
} from "./helpers"

const mocks = vi.hoisted(() => ({
	getConfigs: vi.fn(),
	sqsSend: vi.fn(),
	storeFailure: vi.fn(),
	getFailures: vi.fn(),
	storeAlert: vi.fn(),
}))

vi.mock("@aws-sdk/client-sqs", async (importActual) => ({
	...(await importActual<typeof import("@aws-sdk/client-sqs")>()),
	SQSClient: class {
		send = mocks.sqsSend
	},
}))
vi.mock("../src/repositories/authFailures", () => ({
	storeAuthActivityFailure: mocks.storeFailure,
	getRecentAuthFailuresByIp: mocks.getFailures,
}))
vi.mock("../src/repositories/securityAlerts", () => ({
	storeSecurityAlert: mocks.storeAlert,
}))

// The real fetchDetectionRules service runs (registry join, enabled filter,
// missing-config errors); only its DynamoDB Scan is faked. `mocks.getConfigs`
// provides the configuration rows the Scan returns.
vi.mock("@aws-sdk/lib-dynamodb", async (importActual) => ({
	...(await importActual<typeof import("@aws-sdk/lib-dynamodb")>()),
	DynamoDBDocumentClient: {
		from: () => ({ send: async () => ({ Items: await mocks.getConfigs() }) }),
	},
}))

/** Configs for every registered rule; handler resolves them by rule ID. */
const allRuleConfigs = (
	overrides: Partial<Record<string, Parameters<typeof makeConfig>[1]>> = {},
) =>
	[
		BRUTE_FORCE_RULE_ID,
		PASSWORD_SPRAYING_RULE_ID,
		SUCCESS_AFTER_FAILURES_RULE_ID,
		CLOUDTRAIL_TAMPERING_RULE_ID,
	].map((id) => makeConfig(id, overrides[id]))

/**
 * In-memory stand-in for the two DynamoDB tables, mirroring the real
 * repositories' semantics (per-IP query, conditional alert writes).
 */
let failures: AuthenticationFailure[]
let alerts: Map<string, SecurityAlert>

beforeEach(() => {
	failures = []
	alerts = new Map()
	// biome-ignore lint/suspicious/useIterableCallbackReturn: <explanation>
	Object.values(mocks).forEach((m) => m.mockReset())
	silenceConsole()
	vi.stubEnv("DETECTION_RULES_TABLE_NAME", "test-detection-rules")
	clearDetectionRulesCache()

	mocks.getConfigs.mockResolvedValue(allRuleConfigs())
	mocks.sqsSend.mockResolvedValue({})
	mocks.storeFailure.mockImplementation(async (event) => {
		const eventKey = `${new Date(event.time).toISOString()}#${event.metadata.original_event_uid}`

		const isDuplicate = failures.some(
			(f) => f.eventKey === eventKey && f.sourceIp === event.src_endpoint.ip,
		)

		if (isDuplicate) {
			return EVENT_DUPLICATE
		}

		failures.push({
			sourceIp: event.src_endpoint.ip,
			eventKey,
			eventId: event.metadata.original_event_uid,
			eventTime: new Date(event.time).toISOString(),
			username: event.user.name,
		})

		return EVENT_STORED
	})

	mocks.getFailures.mockImplementation(
		async (query: {
			sourceIp: string
			windowStart: number
			windowEnd: number
		}) =>
			failures.filter((f) => {
				const t = Date.parse(f.eventTime)
				return (
					f.sourceIp === query.sourceIp &&
					t >= query.windowStart &&
					t <= query.windowEnd
				)
			}),
	)

	mocks.storeAlert.mockImplementation(async (alert: SecurityAlert) => {
		if (alerts.has(alert.alertId)) return EVENT_DUPLICATE
		alerts.set(alert.alertId, alert)
		return EVENT_STORED
	})
})

const failureRecord = (id: string, o: Parameters<typeof makeEvent>[0] = {}) =>
	makeRecord(id, makeEvent({ id, ...o }))

const alertsByRule = (ruleId: string) =>
	[...alerts.values()].filter((a) => a.ruleId === ruleId)

describe("handler: detection", () => {
	it("five failed attempts against ONE username trigger brute-force and NOT password spraying", async () => {
		const records = Array.from({ length: 5 }, (_, i) =>
			failureRecord(`m${i}`, {
				username: "alice",
				time: BUCKET_START + i * 1000,
			}),
		)

		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([])
		expect(alertsByRule(BRUTE_FORCE_RULE_ID)).toHaveLength(1)
		expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)).toHaveLength(0)
		expect(alertsByRule(BRUTE_FORCE_RULE_ID)[0]).toMatchObject({
			sourceIp: ATTACKER_IP,
			failedAttempts: 5,
		})
	})

	it("four failed attempts trigger nothing", async () => {
		const records = Array.from({ length: 4 }, (_, i) =>
			failureRecord(`m${i}`, { time: BUCKET_START + i * 1000 }),
		)

		await handler(makeSqsEvent(records))

		expect(alerts.size).toBe(0)
	})

	it("five distinct usernames from one IP trigger both rules", async () => {
		// Spraying implies >= 5 failures from the IP, so with default
		// thresholds brute-force fires alongside it.
		const records = Array.from({ length: 5 }, (_, i) =>
			failureRecord(`m${i}`, {
				username: `user${i}`,
				time: BUCKET_START + i * 1000,
			}),
		)

		await handler(makeSqsEvent(records))

		expect(alertsByRule(BRUTE_FORCE_RULE_ID)).toHaveLength(1)
		expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)).toHaveLength(1)
		expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)[0].targetedAccounts).toBe(5)
	})

	it("repeating one username many times never produces a spraying alert", async () => {
		const records = Array.from({ length: 30 }, (_, i) =>
			failureRecord(`m${i}`, {
				username: "alice",
				time: BUCKET_START + i * 1000,
			}),
		)

		await handler(makeSqsEvent(records))

		expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)).toHaveLength(0)
	})

	it("successful logins are never stored as failures and raise no alert on their own", async () => {
		const records = Array.from({ length: 10 }, (_, i) =>
			failureRecord(`m${i}`, { status: 1, time: BUCKET_START + i * 1000 }),
		)

		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([])
		expect(mocks.storeFailure).not.toHaveBeenCalled()
		expect(failures).toHaveLength(0)
		expect(alerts.size).toBe(0)
	})

	it("successful logins do not count toward the failure threshold", async () => {
		const records = [
			...Array.from({ length: 4 }, (_, i) =>
				failureRecord(`f${i}`, { time: BUCKET_START + i * 1000 }),
			),
			failureRecord("ok", { status: 1, time: BUCKET_START + 5000 }),
		]

		await handler(makeSqsEvent(records))

		expect(alerts.size).toBe(0)
	})

	it("failures from different IPs are not aggregated", async () => {
		const records = Array.from({ length: 6 }, (_, i) =>
			failureRecord(`m${i}`, {
				ip: `198.51.100.${i + 1}`,
				time: BUCKET_START + i * 1000,
			}),
		)

		await handler(makeSqsEvent(records))

		expect(alerts.size).toBe(0)
	})

	it("ignores failures outside the detection window", async () => {
		const old = Array.from({ length: 4 }, (_, i) =>
			failureRecord(`old${i}`, { time: BUCKET_START + i * 1000 }),
		)
		const late = failureRecord("late", { time: BUCKET_START + 10 * 60 * 1000 })

		await handler(makeSqsEvent([...old, late]))

		expect(alerts.size).toBe(0)
	})
})

describe("handler: deduplication", () => {
	it("creates only one alert per rule per bucket when the attack continues", async () => {
		const records = Array.from({ length: 12 }, (_, i) =>
			failureRecord(`m${i}`, {
				username: `user${i}`,
				time: BUCKET_START + i * 1000,
			}),
		)

		await handler(makeSqsEvent(records))

		expect(alertsByRule(BRUTE_FORCE_RULE_ID)).toHaveLength(1)
		expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)).toHaveLength(1)
	})

	it("redelivering the same batch does not create new alerts", async () => {
		const records = Array.from({ length: 6 }, (_, i) =>
			failureRecord(`m${i}`, { time: BUCKET_START + i * 1000 }),
		)

		await handler(makeSqsEvent(records))
		const first = alerts.size
		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([])
		expect(first).toBe(1)
		expect(alerts.size).toBe(first)
		expect(failures).toHaveLength(6)
	})

	it("an already-stored alert is not logged as newly created", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => {})
		mocks.storeAlert.mockResolvedValue(EVENT_DUPLICATE)
		const records = Array.from({ length: 5 }, (_, i) =>
			failureRecord(`m${i}`, { time: BUCKET_START + i * 1000 }),
		)

		await handler(makeSqsEvent(records))

		const created = log.mock.calls.filter((c) =>
			String(c[0]).includes("ALERT_CREATED"),
		)
		expect(created).toHaveLength(0)
	})
})

describe("handler: DynamoDB failures", () => {
	it("reports the failing record and everything after it (FIFO order preserved)", async () => {
		const records = ["a", "b", "c", "d"].map((id, i) =>
			failureRecord(id, { time: BUCKET_START + i * 1000 }),
		)
		mocks.getFailures
			.mockImplementationOnce(async () => [])
			.mockRejectedValueOnce(new Error("DynamoDB unavailable"))

		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([
			{ itemIdentifier: "b" },
			{ itemIdentifier: "c" },
			{ itemIdentifier: "d" },
		])
		expect(mocks.storeFailure).toHaveBeenCalledTimes(2)
	})

	it("fails the whole batch when the first write fails", async () => {
		mocks.storeFailure.mockRejectedValue(new Error("DynamoDB unavailable"))
		const records = ["a", "b"].map((id) => failureRecord(id))

		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([
			{ itemIdentifier: "a" },
			{ itemIdentifier: "b" },
		])
	})

	it("fails the record when storing the alert fails, so it is retried", async () => {
		mocks.storeAlert.mockRejectedValue(new Error("DynamoDB unavailable"))
		const records = Array.from({ length: 6 }, (_, i) =>
			failureRecord(`m${i}`, { time: BUCKET_START + i * 1000 }),
		)

		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures.map((f) => f.itemIdentifier)).toEqual([
			"m4",
			"m5",
		])
	})

	it("logs the processing failure without leaking a thrown non-Error as a crash", async () => {
		mocks.storeFailure.mockRejectedValue("boom")

		const result = await handler(makeSqsEvent([failureRecord("a")]))

		expect(result.batchItemFailures).toEqual([{ itemIdentifier: "a" }])
	})
})

describe("handler: malformed input", () => {
	it("quarantines invalid JSON and does not fail the batch", async () => {
		const result = await handler(makeSqsEvent([makeRecord("bad", "{not json")]))

		expect(result.batchItemFailures).toEqual([])
		expect(mocks.sqsSend).toHaveBeenCalledOnce()
		const body = JSON.parse(mocks.sqsSend.mock.calls[0][0].input.MessageBody)
		expect(body).toMatchObject({
			originalMessageId: "bad",
			reason: "INVALID_JSON",
		})
		expect(mocks.storeFailure).not.toHaveBeenCalled()
	})

	it("quarantines events that fail schema validation", async () => {
		const bad = { ...makeEvent(), src_endpoint: { ip: "999.999.999.999" } }

		const result = await handler(makeSqsEvent([makeRecord("invalid", bad)]))

		expect(result.batchItemFailures).toEqual([])
		const body = JSON.parse(mocks.sqsSend.mock.calls[0][0].input.MessageBody)
		expect(body).toMatchObject({
			originalMessageId: "invalid",
			reason: "OCSF_SCHEMA_VALIDATION_FAILED",
		})
		expect(mocks.storeFailure).not.toHaveBeenCalled()
	})

	it("keeps processing valid records after a quarantined one", async () => {
		const records = [
			makeRecord("bad", "{not json"),
			...Array.from({ length: 5 }, (_, i) =>
				failureRecord(`m${i}`, { time: BUCKET_START + i * 1000 }),
			),
		]

		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([])
		expect(alertsByRule(BRUTE_FORCE_RULE_ID)).toHaveLength(1)
	})

	it("fails the batch when quarantining itself fails", async () => {
		mocks.sqsSend.mockRejectedValue(new Error("SQS unavailable"))

		const result = await handler(makeSqsEvent([makeRecord("bad", "{not json")]))

		expect(result.batchItemFailures).toEqual([{ itemIdentifier: "bad" }])
	})
})


describe("handler: configured rules", () => {
 it("stores events with all rules disabled without querying history", async () => {
  mocks.getConfigs.mockResolvedValue(
   allRuleConfigs({
    [BRUTE_FORCE_RULE_ID]: { enabled: false },
    [PASSWORD_SPRAYING_RULE_ID]: { enabled: false },
    [SUCCESS_AFTER_FAILURES_RULE_ID]: { enabled: false },
   }),
  )
  const log = vi.mocked(console.log)
  const result = await handler(makeSqsEvent([failureRecord("a")]))
  expect(result.batchItemFailures).toEqual([])
  expect(mocks.storeFailure).toHaveBeenCalledOnce()
  expect(mocks.getFailures).not.toHaveBeenCalled()
  expect(mocks.storeAlert).not.toHaveBeenCalled()
  expect(JSON.parse(String(log.mock.calls.at(-1)?.[0]))).toMatchObject({
   processedEvents: 1, eventsWithoutAlerts: 1, detectedAlerts: 0,
  })
 })

 it("uses only enabled windows and matches unordered configs by ID", async () => {
  // Deliberately unordered: configs must be matched to rules by ID.
  mocks.getConfigs.mockResolvedValue([
   makeConfig(CLOUDTRAIL_TAMPERING_RULE_ID, { enabled: false }),
   makeConfig(SUCCESS_AFTER_FAILURES_RULE_ID, { enabled: false, windowSeconds: 900 }),
   makeConfig(PASSWORD_SPRAYING_RULE_ID, { enabled: false, windowSeconds: 600 }),
   makeConfig(BRUTE_FORCE_RULE_ID, { threshold: 1, windowSeconds: 30, severity: "critical" }),
  ])
  const time = BUCKET_START + 120_000
  const result = await handler(makeSqsEvent([failureRecord("a", { time })]))
  expect(result.batchItemFailures).toEqual([])
  expect(mocks.getConfigs).toHaveBeenCalledOnce()
  expect(mocks.getFailures).toHaveBeenCalledExactlyOnceWith({
   sourceIp: ATTACKER_IP, windowStart: time - 30_000, windowEnd: time,
  })
  expect(alertsByRule(BRUTE_FORCE_RULE_ID)[0]).toMatchObject({ severity: "critical", failedAttempts: 1 })
  expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)).toHaveLength(0)
 })

 it("queries once per event for the longest window while each rule filters its own history", async () => {
  mocks.getConfigs.mockResolvedValue(
   allRuleConfigs({
    [BRUTE_FORCE_RULE_ID]: { threshold: 2, windowSeconds: 30 },
    [PASSWORD_SPRAYING_RULE_ID]: { threshold: 2, windowSeconds: 120, severity: "medium" },
    [SUCCESS_AFTER_FAILURES_RULE_ID]: { enabled: false },
   }),
  )
  const end = BUCKET_START + 120_000
  const records = [
   failureRecord("old", { username: "alice", time: end - 60_000 }),
   failureRecord("new", { username: "bob", time: end }),
  ]
  expect((await handler(makeSqsEvent(records))).batchItemFailures).toEqual([])
  expect(mocks.getFailures).toHaveBeenCalledTimes(2)
  expect(mocks.getFailures).toHaveBeenLastCalledWith({ sourceIp: ATTACKER_IP, windowStart: end - 120_000, windowEnd: end })
  expect(alertsByRule(BRUTE_FORCE_RULE_ID)).toHaveLength(0)
  expect(alertsByRule(PASSWORD_SPRAYING_RULE_ID)[0]).toMatchObject({ targetedAccounts: 2, severity: "medium" })
 })

 it.each(["unavailable", "missing"])("retries current and remaining FIFO records when configuration is %s", async (mode) => {
  if (mode === "unavailable") mocks.getConfigs.mockRejectedValueOnce(new Error("Access denied"))
  else mocks.getConfigs.mockResolvedValueOnce([makeConfig(BRUTE_FORCE_RULE_ID, { enabled: false })])
  const result = await handler(makeSqsEvent([failureRecord("a"), failureRecord("b")]))
  expect(result.batchItemFailures).toEqual([{ itemIdentifier: "a" }, { itemIdentifier: "b" }])
  expect(mocks.storeFailure).toHaveBeenCalledOnce()
  expect(mocks.getFailures).not.toHaveBeenCalled()
  expect(mocks.sqsSend).not.toHaveBeenCalled()
  expect(mocks.storeAlert).not.toHaveBeenCalled()
 })
})


describe("handler: successful login after failures", () => {
	const failuresThenLogin = (failureCount: number, loginUser = "alice") => [
		...Array.from({ length: failureCount }, (_, i) =>
			failureRecord(`f${i}`, {
				username: "alice",
				time: BUCKET_START + i * 1000,
			}),
		),
		failureRecord("login", {
			username: loginUser,
			status: 1,
			time: BUCKET_START + 60_000,
		}),
	]

	it("raises an alert when a login succeeds after enough failures", async () => {
		// Five failures also trip brute-force on the 5th failure; only the
		// success-after-failures alert is asserted here.
		const result = await handler(makeSqsEvent(failuresThenLogin(5)))

		expect(result.batchItemFailures).toEqual([])
		const found = alertsByRule(SUCCESS_AFTER_FAILURES_RULE_ID)
		expect(found).toHaveLength(1)
		expect(found[0]).toMatchObject({
			sourceIp: ATTACKER_IP,
			failedAttempts: 5,
			usernames: ["alice"],
		})
	})

	it("does not alert below the threshold", async () => {
		await handler(makeSqsEvent(failuresThenLogin(4)))

		expect(alertsByRule(SUCCESS_AFTER_FAILURES_RULE_ID)).toHaveLength(0)
	})

	it("does not alert when the successful login is for a different user", async () => {
		await handler(makeSqsEvent(failuresThenLogin(5, "bob")))

		expect(alertsByRule(SUCCESS_AFTER_FAILURES_RULE_ID)).toHaveLength(0)
	})

	it("does not store the successful login as a failure", async () => {
		await handler(makeSqsEvent(failuresThenLogin(5)))

		expect(mocks.storeFailure).toHaveBeenCalledTimes(5)
		expect(failures).toHaveLength(5)
		expect(failures.every((f) => f.eventId !== "login")).toBe(true)
	})

	it("redelivering the batch does not duplicate the alert", async () => {
		const records = failuresThenLogin(5)

		await handler(makeSqsEvent(records))
		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([])
		expect(alertsByRule(SUCCESS_AFTER_FAILURES_RULE_ID)).toHaveLength(1)
	})

	it("does not alert when the rule is disabled", async () => {
		mocks.getConfigs.mockResolvedValue(
			allRuleConfigs({
				[SUCCESS_AFTER_FAILURES_RULE_ID]: { enabled: false },
			}),
		)

		await handler(makeSqsEvent(failuresThenLogin(5)))

		expect(alertsByRule(SUCCESS_AFTER_FAILURES_RULE_ID)).toHaveLength(0)
		expect(alertsByRule(BRUTE_FORCE_RULE_ID)).toHaveLength(1)
	})

	it("reports the alert in the batch summary", async () => {
		const log = vi.mocked(console.log)

		await handler(makeSqsEvent(failuresThenLogin(5)))

		const summary = JSON.parse(String(log.mock.calls.at(-1)?.[0]))
		expect(summary).toMatchObject({
			receivedEvents: 6,
			processedEvents: 6,
		})
		expect(summary.alertsByRule[SUCCESS_AFTER_FAILURES_RULE_ID]).toBe(1)
	})
})


describe("handler: CloudTrail tampering", () => {
	const tamperingRecord = (
		id: string,
		o: Parameters<typeof makeCloudTrailEvent>[0] = {},
	) => makeRecord(id, makeCloudTrailEvent(o))

	const tamperingAlerts = () => alertsByRule(CLOUDTRAIL_TAMPERING_RULE_ID)

	it("raises an alert for a successful StopLogging", async () => {
		const result = await handler(makeSqsEvent([tamperingRecord("a")]))

		expect(result.batchItemFailures).toEqual([])
		expect(tamperingAlerts()).toHaveLength(1)
		expect(tamperingAlerts()[0]).toMatchObject({
			ruleId: CLOUDTRAIL_TAMPERING_RULE_ID,
			actor: "AccountFullAccessRole",
			status: "open",
		})
	})

	it("raises an alert when the CloudTrail log bucket is deleted", async () => {
		await handler(
			makeSqsEvent([
				tamperingRecord("a", {
					operation: "DeleteBucket",
					service: "s3.amazonaws.com",
					bucketName: CLOUDTRAIL_LOG_BUCKET_NAME,
				}),
			]),
		)

		expect(tamperingAlerts()).toHaveLength(1)
		expect(tamperingAlerts()[0].description).toContain(CLOUDTRAIL_LOG_BUCKET_NAME)
	})

	it("does not alert for a failed call or an unrelated operation", async () => {
		await handler(
			makeSqsEvent([
				tamperingRecord("denied", { status: 2 }),
				tamperingRecord("other", { operation: "DescribeTrails" }),
			]),
		)

		expect(tamperingAlerts()).toHaveLength(0)
		expect(mocks.storeAlert).not.toHaveBeenCalled()
	})

	it("does not query authentication history or store failures", async () => {
		await handler(makeSqsEvent([tamperingRecord("a")]))

		expect(mocks.getFailures).not.toHaveBeenCalled()
		expect(mocks.storeFailure).not.toHaveBeenCalled()
	})

	it("creates one alert per tampering call, even from the same actor", async () => {
		await handler(
			makeSqsEvent([
				tamperingRecord("a", { operation: "StopLogging" }),
				tamperingRecord("b", { operation: "DeleteTrail" }),
			]),
		)

		expect(tamperingAlerts()).toHaveLength(2)
	})

	it("keeps alerting on later calls by an actor that already triggered an alert", async () => {
		await handler(makeSqsEvent([tamperingRecord("first")]))
		await handler(makeSqsEvent([tamperingRecord("second")]))

		expect(tamperingAlerts()).toHaveLength(2)
	})

	it("creates separate alerts for different actors", async () => {
		await handler(
			makeSqsEvent([
				tamperingRecord("a", { actorName: "alice-role" }),
				tamperingRecord("b", { actorName: "bob-role" }),
			]),
		)

		expect(tamperingAlerts().map((a) => a.actor).sort()).toEqual([
			"alice-role",
			"bob-role",
		])
	})

	it("redelivering the batch does not duplicate the alert", async () => {
		const records = [tamperingRecord("a")]

		await handler(makeSqsEvent(records))
		const result = await handler(makeSqsEvent(records))

		expect(result.batchItemFailures).toEqual([])
		expect(tamperingAlerts()).toHaveLength(1)
	})

	it("does not alert when the rule is disabled", async () => {
		mocks.getConfigs.mockResolvedValue(
			allRuleConfigs({ [CLOUDTRAIL_TAMPERING_RULE_ID]: { enabled: false } }),
		)

		const result = await handler(makeSqsEvent([tamperingRecord("a")]))

		expect(result.batchItemFailures).toEqual([])
		expect(tamperingAlerts()).toHaveLength(0)
	})

	it("quarantines a CloudTrail event that fails schema validation", async () => {
		const invalid = { ...makeCloudTrailEvent(), api: undefined }

		const result = await handler(makeSqsEvent([makeRecord("bad", invalid)]))

		expect(result.batchItemFailures).toEqual([])
		expect(mocks.sqsSend).toHaveBeenCalledOnce()
		expect(mocks.storeAlert).not.toHaveBeenCalled()
	})

	it("retries the record when the rule configuration is unavailable", async () => {
		mocks.getConfigs.mockRejectedValueOnce(new Error("Access denied"))

		const result = await handler(makeSqsEvent([tamperingRecord("a")]))

		expect(result.batchItemFailures).toEqual([{ itemIdentifier: "a" }])
		expect(mocks.storeAlert).not.toHaveBeenCalled()
	})

	it("reports the alert in the batch summary", async () => {
		const log = vi.mocked(console.log)

		await handler(makeSqsEvent([tamperingRecord("a")]))

		const summary = JSON.parse(String(log.mock.calls.at(-1)?.[0]))
		expect(summary).toMatchObject({ receivedEvents: 1, processedEvents: 1 })
		expect(summary.alertsByRule[CLOUDTRAIL_TAMPERING_RULE_ID]).toBe(1)
	})
})
