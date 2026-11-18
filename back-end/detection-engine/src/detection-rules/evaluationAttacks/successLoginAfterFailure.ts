import type {
	AuthenticationFailure,
	DetectionRule,
	OCSFAuthenticationEvent,
	RuleEvaluationResult,
} from "../../types"
import { DETECTION_RULES } from "../detectionRules"
import { isEligibleAuthEvent } from "../helpers"

export const evaluateForSuccessLoginAfterFailure = (
	event: OCSFAuthenticationEvent,
	recentFailures: AuthenticationFailure[],
	config: DetectionRule,
): RuleEvaluationResult => {
	const ruleId =
		DETECTION_RULES.Authentication.SUCCESS_LOGIN_AFTER_FAILURES.ruleId
	const ruleName =
		DETECTION_RULES.Authentication.SUCCESS_LOGIN_AFTER_FAILURES.ruleName

	// Ignore events that dont qualify for the evaluation
	if (!isEligibleAuthEvent(event, "successLogin")) {
		return { detected: false }
	}

	const sourceIp = event.src_endpoint.ip
	const eventTime = event.time

	// Convert rule's configured time interval from seconds to milliseconds.
	const windowStart = eventTime - (config.windowSeconds ?? 0) * 1000

	// Count only authentication failures within this rule's time window.
	const failuresWithinInterval = recentFailures.filter((failure) => {
		const failureTime = Date.parse(failure.eventTime)

		return (
			failure.sourceIp === sourceIp &&
			failure.username === event.user.name &&
			Number.isFinite(failureTime) &&
			failureTime >= windowStart &&
			failureTime < eventTime
		)
	})

	const failedAttempts = failuresWithinInterval.length

	// return NO ISSUE detected when login attempts are lower than threshold in the rule config
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
				`Successful authentication for ${event.user.name} from ${sourceIp} ` +
				`following ${failedAttempts} failed attempts within ` +
				`${config.windowSeconds} seconds.`,
			metadata: {
				failedAttempts,
				usernames: [event.user.name],
			},
		},
	}
}
