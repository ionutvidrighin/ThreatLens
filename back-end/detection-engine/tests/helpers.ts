import type { SQSEvent, SQSRecord } from "aws-lambda"
import { vi } from "vitest"
const WINDOW_SECONDS = 300
import { DETECTION_RULES } from "../src/detection-rules/detectionRules"
import type {
	AuthenticationFailure,
	DetectionRule,
	OCSFAuthenticationEvent,
	OCSFCloudTrailEvent,
} from "../src/types"

const WINDOW_MS = WINDOW_SECONDS * 1000

export const BRUTE_FORCE_RULE_ID =
	DETECTION_RULES.Authentication.BRUTE_FORCE.ruleId
export const PASSWORD_SPRAYING_RULE_ID =
	DETECTION_RULES.Authentication.PASSWORD_SPRAYING.ruleId
export const SUCCESS_AFTER_FAILURES_RULE_ID =
	DETECTION_RULES.Authentication.SUCCESS_LOGIN_AFTER_FAILURES.ruleId
export const CLOUDTRAIL_TAMPERING_RULE_ID =
	DETECTION_RULES["Cloud-Infrastructure"].CLOUDTRAIL_TAMPERING.ruleId

/** Start of a detection bucket, so test events never straddle a boundary. */
export const BUCKET_START =
	Math.floor(1_800_000_000_000 / WINDOW_MS) * WINDOW_MS
export const ATTACKER_IP = "203.0.113.10"

type EventOverrides = {
	username?: string
	ip?: string
	time?: number
	id?: string
	/** 1 = success, 2 = failure */
	status?: 1 | 2
}

let counter = 0

export function makeEvent(o: EventOverrides = {}): OCSFAuthenticationEvent {
	counter++
	const ip = o.ip ?? ATTACKER_IP
	return {
		class_uid: 3002,
		category_uid: 3,
		activity_id: 1,
		type_uid: 300201,
		time: o.time ?? BUCKET_START + 120_000,
		severity_id: 1,
		status_id: o.status ?? 2,
		metadata: {
			version: "1.0.0",
			product: { name: "TestApp", vendor_name: "Test" },
			original_event_uid: o.id ?? `evt-${counter}`,
		},
		user: { name: o.username ?? "alice" },
		src_endpoint: { ip },
		observables: [{ name: "src_ip", type_id: 2, value: ip }],
		raw_data: "raw",
	} as OCSFAuthenticationEvent
}

export function makeFailures(
	usernames: (string | undefined)[],
): AuthenticationFailure[] {
	return usernames.map((username, i) => ({
		sourceIp: ATTACKER_IP,
		eventKey: `${new Date(BUCKET_START + i * 1000).toISOString()}#e${i}`,
		eventId: `e${i}`,
		eventTime: new Date(BUCKET_START + i * 1000).toISOString(),
		username,
	}))
}

export function makeRecord(messageId: string, body: unknown): SQSRecord {
	return {
		messageId,
		body: typeof body === "string" ? body : JSON.stringify(body),
	} as SQSRecord
}

export function makeSqsEvent(records: SQSRecord[]): SQSEvent {
	return { Records: records }
}

export function silenceConsole() {
	return {
		log: vi.spyOn(console, "log").mockImplementation(() => {}),
		warn: vi.spyOn(console, "warn").mockImplementation(() => {}),
		error: vi.spyOn(console, "error").mockImplementation(() => {}),
	}
}

export function makeConfig(
	ruleId: string,
	overrides: Partial<DetectionRule> = {},
): DetectionRule {
	return {
		ruleId,
		enabled: true,
		category: "Authentication",
		label: "Test rule",
		threshold: 5,
		windowSeconds: 300,
		severity: "high",
		updatedAt: "2026-11-11T00:00:00.000Z",
		...overrides,
	}
}

type CloudTrailEventOverrides = {
	operation?: string
	service?: string
	/** 1 = success, 2 = failure */
	status?: 0 | 1 | 2 | 99
	actorName?: string
	actorUid?: string
	ip?: string
	time?: number
	/** S3 bucket the call targeted (requestParameters.bucketName) */
	bucketName?: string
}

export const CLOUDTRAIL_LOG_BUCKET_NAME =
	"aws-cloudtrail-logs-123456789012-5e41818d"

/** A successful `StopLogging` call by default, i.e. a tampering event. */
export function makeCloudTrailEvent(
	o: CloudTrailEventOverrides = {},
): OCSFCloudTrailEvent {
	counter++
	return {
		class_uid: 6003,
		category_uid: 6,
		activity_id: 99,
		type_uid: 600399,
		time: o.time ?? BUCKET_START + 120_000,
		severity_id: 1,
		status_id: o.status ?? 1,
		metadata: {
			version: "1.3.0",
			product: { name: "ThreatLens", vendor_name: "ThreatLens" },
			original_event_uid: `ct-${counter}`,
		},
		actor: {
			user: {
				name: o.actorName ?? "AccountFullAccessRole",
				uid: o.actorUid ?? "AROAEXAMPLE:session",
				type: "AssumedRole",
				account: { uid: "123456789012" },
			},
		},
		api: {
			operation: o.operation ?? "StopLogging",
			service: { name: o.service ?? "cloudtrail.amazonaws.com" },
		},
		cloud: { region: "eu-north-1", account: { uid: "123456789012" } },
		src_endpoint: { ip: o.ip ?? ATTACKER_IP },
		requestParameters: o.bucketName ? { bucketName: o.bucketName } : undefined,
		raw_data: "raw",
	} as OCSFCloudTrailEvent
}
