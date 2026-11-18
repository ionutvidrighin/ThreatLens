import type { z } from "zod"
import type { DetectionRuleId } from "./detection-rules/detectionRules"
import type { DetectionRuleSchema } from "./schemas/detectionRuleConfig.schema"
import type { OCSFAuthenticationSchema } from "./schemas/ocsfAuthentication.schema"
import type { OCSFCloudTrailSchema } from "./schemas/ocsfCloudTrail.schema"

export type OCSFAuthenticationEvent = z.infer<typeof OCSFAuthenticationSchema>
export type OCSFCloudTrailEvent = z.infer<typeof OCSFCloudTrailSchema>

export type DetectionRule = z.infer<typeof DetectionRuleSchema>

export type ProcessedEventOutcome =
	| { status: "quarantined" }
	| { status: "ignored" }
	| { status: "processed"; alerts: AlertOrchestrationResult[] }

export type PasswordSprayingResult = {
	detected: boolean
	alertId?: string
	sourceIp?: string
	targetedAccounts: number
	usernames: string[]
}

export type SecurityAlert = {
	alertId: string
	entityType: "ALERT"
	ruleId: string
	ruleName: string
	severity: "low" | "medium" | "high" | "critical"
	status: "open"
	sourceIp: string
	actor?: string
	windowStart: string
	windowEnd: string
	createdAt: string
	description: string
	failedAttempts?: number
	targetedAccounts?: number
	usernames?: string[]
}

export type AuthenticationFailure = {
	sourceIp: string
	eventKey: string
	eventId: string
	eventTime: string
	username?: string
}

export type AuthenticationRuleContext = {
	event: OCSFAuthenticationEvent
	recentFailures: AuthenticationFailure[]
	configuration: DetectionRule
}

export type CloudTrailRuleContext = {
	event: OCSFCloudTrailEvent
	configuration: DetectionRule
}

export type RuleResult = {
	detected: boolean
	alertId?: string
	sourceIp?: string
}

export type DetectionResult = {
	detected: boolean
	alertId?: string
	sourceIp?: string
	failedAttempts?: number
	duplicateEvent?: boolean
}

/** A rule declares which kind of event it evaluates; `eventType` narrows `evaluate`. */
export type DetectionRuleWithEvalution =
	| {
			id: DetectionRuleId
			eventType: "authentication"
			evaluate: (context: AuthenticationRuleContext) => RuleEvaluationResult
	  }
	| {
			id: DetectionRuleId
			eventType: "cloudtrail"
			evaluate: (context: CloudTrailRuleContext) => RuleEvaluationResult
	  }

export type DetectionFinding = {
	ruleId: string
	ruleName: string
	severity: "low" | "medium" | "high" | "critical"
	sourceIp: string
	actor?: string
	/**
	 * Source event ID. Stateless rules (windowSeconds: 0) set it: with no time
	 * window, the event itself is what identifies (and deduplicates) the alert.
	 */
	eventId?: string
	eventTime: number
	windowSeconds: number
	description: string
	metadata: {
		failedAttempts?: number
		targetedAccounts?: number
		usernames?: string[]
	}
}

export type RuleEvaluationResult =
	| {
			detected: false
	  }
	| {
			detected: true
			finding: DetectionFinding
	  }

export type AlertOrchestrationResult = {
	created: boolean
	alertId: string
	ruleId: string
	sourceIp: string
}

export type RuleConfigCache = {
	ruleIds: string[]
	configurations: DetectionRule[]
	expiresAt: number
}

export type QuarantineReason = "INVALID_JSON" | "OCSF_SCHEMA_VALIDATION_FAILED"

export type QuarantineInput = {
	messageId: string
	body: string
	reason: QuarantineReason
	validationErrors: unknown[]
}
