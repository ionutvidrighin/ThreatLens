import type {
	DetectionRule,
	OCSFCloudTrailEvent,
	RuleEvaluationResult,
} from "../../types"
import { DETECTION_RULES } from "../detectionRules"
import { isEligileCloudTrailEvent } from "../helpers"
import { OCSF_EVENT_CLASSES } from "../OCSFeventClasses"

/**
 * Stateless rule: a single successful call that tampers with CloudTrail or its
 * log bucket is already suspicious, so no history is needed.
 */
export const evaluateForCloudTrailTampering = (
	event: OCSFCloudTrailEvent,
	config: DetectionRule,
): RuleEvaluationResult => {
	const { ruleId, ruleName } =
		DETECTION_RULES["Cloud-Infrastructure"].CLOUDTRAIL_TAMPERING

	const eventStatus =
		OCSF_EVENT_CLASSES.applicationActivity.apiActivity.statuses

	// Only successful calls count
	if (event.status_id !== eventStatus.success) {
		return { detected: false }
	}

	if (!isEligileCloudTrailEvent(event)) {
		return { detected: false }
	}

	const actor = event.actor.user.name ?? event.actor.user.uid ?? "unknown actor"
	const target = event.requestParameters?.bucketName
	const eventOperation = event.api.operation

	const isCriticalSeverity =
		eventOperation === "StopLogging" || eventOperation === "DeleteTrail"

	return {
		detected: true,
		finding: {
			ruleId,
			ruleName,
			severity: isCriticalSeverity ? "critical" : config.severity,
			actor,
			eventId: event.metadata.original_event_uid,
			sourceIp: event.src_endpoint?.ip ?? "unknown",
			eventTime: event.time,
			windowSeconds: 0,
			description:
				`${actor} called ${event.api.operation} on ${event.api.service.name}` +
				(target ? ` (${target})` : "") +
				", which can disable or destroy activity logs.",
			metadata: {},
		},
	}
}
