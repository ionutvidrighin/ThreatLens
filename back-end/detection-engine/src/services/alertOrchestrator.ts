import { EVENT_STORED } from "../constants"
import { storeSecurityAlert } from "../repositories/securityAlerts"
import type {
	AlertOrchestrationResult,
	DetectionFinding,
	SecurityAlert,
} from "../types"

import { createAlertId } from "../utils/common"

export const orchestrateAlert = async (
	finding: DetectionFinding,
): Promise<AlertOrchestrationResult> => {
	const {
		ruleId,
		ruleName,
		severity,
		sourceIp,
		actor,
		eventId,
		eventTime,
		windowSeconds,
		description,
		metadata,
	} = finding

	const windowMilliseconds = windowSeconds * 1000

	// Deterministic deduplication key. Windowed rules share one alert per time
	// bucket; stateless rules (no window) get one alert per source event.
	let dedupeKey: string | number

	if (windowMilliseconds > 0) {
		dedupeKey =
			Math.floor(eventTime / windowMilliseconds) * windowMilliseconds
	} else if (eventId) {
		dedupeKey = eventId
	} else {
		// Without either, every alert would get the same ID and be dropped as a duplicate
		throw new Error(
			`Finding for ${ruleId} needs a window or an eventId to build its alertId`,
		)
	}

	// Include the detection rule ID to prevent collisions between detection rules.
	// The alert is about the actor when there is one (CloudTrail calls are not
	// always tied to a useful IP), otherwise about the source IP.
	const alertId = createAlertId(ruleId, actor ?? sourceIp, dedupeKey)

	// Build the alert using the shared security alert contract.
	const alert: SecurityAlert = {
		alertId,
		entityType: "ALERT",
		ruleId,
		ruleName,
		severity,
		status: "open",
		sourceIp,
		...(actor && { actor }),
		windowStart: new Date(
			Math.max(0, eventTime - windowMilliseconds),
		).toISOString(),
		windowEnd: new Date(eventTime).toISOString(),
		createdAt: new Date().toISOString(),
		description,
		...metadata,
	}

	//store the alert to DynamoDB
	const storeEventResult = await storeSecurityAlert(alert)

	return {
		created: storeEventResult === EVENT_STORED,
		alertId,
		ruleId,
		sourceIp,
	}
}
