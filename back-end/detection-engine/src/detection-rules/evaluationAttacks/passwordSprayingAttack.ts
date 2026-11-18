import type {
	AuthenticationFailure,
	DetectionRule,
	OCSFAuthenticationEvent,
	RuleEvaluationResult,
} from "../../types"
import { DETECTION_RULES } from "../detectionRules"
import { isEligibleAuthEvent } from "../helpers"

export const evaluateForPasswordSprayingAttack = (
	event: OCSFAuthenticationEvent,
	recentFailures: AuthenticationFailure[],
	config: DetectionRule,
): RuleEvaluationResult => {
	const ruleId = DETECTION_RULES.Authentication.PASSWORD_SPRAYING.ruleId
	const ruleName = DETECTION_RULES.Authentication.PASSWORD_SPRAYING.ruleName

	// Ignore events that dont qualify for the evaluation
	if (!isEligibleAuthEvent(event, "failedLogin")) {
		return { detected: false }
	}

	const sourceIp = event.src_endpoint.ip
	const eventTime = event.time
	const windowStart = eventTime - (config.windowSeconds ?? 0) * 1000

	// Keep only failures within this rule's configured time window.
	const failureLoginsWithinTimeInterval = recentFailures.filter((failure) => {
		const failureTime = Date.parse(failure.eventTime)

		return (
			Number.isFinite(failureTime) &&
			failureTime >= windowStart &&
			failureTime <= eventTime
		)
	})

	const filteredElementsByUsername = failureLoginsWithinTimeInterval
		.map((element) => element.username?.trim())
		.filter(
			(username): username is string =>
				typeof username === "string" && username.length > 0,
		)

	// Count distinct usernames targeted by the source IP.
	const usernames = [...new Set(filteredElementsByUsername)]

	const targetedAccounts = usernames.length

	// return NO ISSUE detected when login attempts are lower than threshold
	if (targetedAccounts < (config.threshold ?? 0)) {
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
				`${targetedAccounts} distinct accounts experienced failed ` +
				`authentication attempts from ${sourceIp} within ` +
				`${config.windowSeconds} seconds.`,
			metadata: {
				targetedAccounts,
				usernames,
			},
		},
	}
}
