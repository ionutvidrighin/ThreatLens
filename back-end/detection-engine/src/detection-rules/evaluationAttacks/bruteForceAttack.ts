import type {
	AuthenticationFailure,
	DetectionRule,
	OCSFAuthenticationEvent,
	RuleEvaluationResult,
} from "../../types"
import { DETECTION_RULES } from "../detectionRules"
import { isEligibleAuthEvent } from "../helpers"

export const evaluateForBruteForceAttack = (
	event: OCSFAuthenticationEvent,
	recentFailures: AuthenticationFailure[],
	config: DetectionRule,
): RuleEvaluationResult => {
	const ruleId = DETECTION_RULES.Authentication.BRUTE_FORCE.ruleId
	const ruleName = DETECTION_RULES.Authentication.BRUTE_FORCE.ruleName

	// Ignore events that dont qualify for the evaluation
	if (!isEligibleAuthEvent(event, "failedLogin")) {
		return { detected: false }
	}

	const sourceIp = event.src_endpoint.ip
	const eventTime = event.time

	// Convert the configured window from seconds to milliseconds.
	const windowStart = eventTime - (config.windowSeconds ?? 0) * 1000

	// Count only authentication failures within this rule's time window.
	const failuresWithinWindow = recentFailures.filter((failure) => {
		const failureTime = Date.parse(failure.eventTime)

		return (
			Number.isFinite(failureTime) &&
			failureTime >= windowStart &&
			failureTime <= eventTime
		)
	})

	const failedAttempts = failuresWithinWindow.length
	const affectedAccounts = failuresWithinWindow
		.map((failedEvent) => failedEvent.username)
		.filter((item) => item !== undefined)

	// return NO ISSUE detected when login attempts are lower than threshold
	if (failedAttempts < (config.threshold ?? 0)) {
		return { detected: false }
	}

	// otherwise return the finding
	return {
		detected: true,
		finding: {
			ruleId,
			ruleName,
			severity: config.severity,
			sourceIp,
			eventTime,
			windowSeconds: config.windowSeconds ?? 0,
			description:
				`${failedAttempts} failed authentication attempts ` +
				`detected from ${sourceIp} within ${config.windowSeconds} seconds.`,
			metadata: {
				failedAttempts,
				usernames: [...new Set(affectedAccounts)],
			},
		},
	}
}
