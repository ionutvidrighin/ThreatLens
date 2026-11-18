import { getRecentAuthFailuresByIp } from "../repositories/authFailures"
import type {
	AlertOrchestrationResult,
	DetectionFinding,
	OCSFAuthenticationEvent,
	OCSFCloudTrailEvent,
} from "../types"
import { logger } from "../utils/logger"
import { orchestrateAlert } from "./alertOrchestrator"
import { fetchDetectionRules } from "./fetchDetectionRulesService"

/** Persist findings as alerts. Returns only the alerts that were newly created. */
const createAlertsFromFindings = async (
	findings: DetectionFinding[],
): Promise<AlertOrchestrationResult[]> => {
	const createdAlerts: AlertOrchestrationResult[] = []

	for (const finding of findings) {
		const alert = await orchestrateAlert(finding)

		if (!alert.created) {
			continue
		}

		createdAlerts.push(alert)

		logger.info("ALERT_CREATED", {
			ruleId: alert.ruleId,
			alertId: alert.alertId,
			sourceIp: alert.sourceIp,
			actor: finding.actor,
		})
	}

	return createdAlerts
}

/**
 * Evaluate every active/enabled authentication rule against one event and
 * persist resulting alerts. Returns only the alerts that were newly created
 * (duplicates are skipped).
 */
export const evaluateAuthDetectionRules = async (
	event: OCSFAuthenticationEvent,
): Promise<AlertOrchestrationResult[]> => {
	const activeRules = (await fetchDetectionRules()).flatMap(
		({ detectionRule, configuration }) =>
			detectionRule.eventType === "authentication"
				? [{ detectionRule, configuration }]
				: [],
	)

	// When no active rule, dont evaluate anything
	if (activeRules.length === 0) {
		return []
	}

	// Query history once per event, wide enough for the longest rule window.
	const maxWindowSeconds = Math.max(
		...activeRules.map(({ configuration }) => configuration.windowSeconds ?? 0),
	)
	const recentFailureLoginsByIp = await getRecentAuthFailuresByIp({
		sourceIp: event.src_endpoint.ip,
		windowStart: event.time - maxWindowSeconds * 1000,
		windowEnd: event.time,
	})

	const findings: DetectionFinding[] = []

	for (const { detectionRule, configuration } of activeRules) {
		const evaluation = detectionRule.evaluate({
			event,
			recentFailures: recentFailureLoginsByIp,
			configuration,
		})

		if (evaluation.detected) {
			findings.push(evaluation.finding)
		}
	}

	return createAlertsFromFindings(findings)
}

/** Same as evaluateDetectionRules, for CloudTrail (API activity) events. */
export const evaluateCloudTrailRules = async (
	event: OCSFCloudTrailEvent,
): Promise<AlertOrchestrationResult[]> => {
	const fetchedRules = await fetchDetectionRules()

	const activeRules = fetchedRules.flatMap(
		({ detectionRule, configuration }) =>
			detectionRule.eventType === "cloudtrail"
				? [{ detectionRule, configuration }]
				: [],
	)

	const findings: DetectionFinding[] = []

	for (const { detectionRule, configuration } of activeRules) {
		const evaluation = detectionRule.evaluate({ event, configuration })

		if (evaluation.detected) {
			findings.push(evaluation.finding)
		}
	}

	return createAlertsFromFindings(findings)
}
