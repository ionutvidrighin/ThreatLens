import type { ProcessedEventOutcome } from "../types"

export const createBatchMetrics = (receivedEvents: number) => {
	let processedEvents = 0
	let ignoredEvents = 0
	let quarantinedEvents = 0
	let eventsWithoutAlerts = 0
	let detectedAlerts = 0
	const alertsByRule: Record<string, number> = {}

	return {
		record(outcome: ProcessedEventOutcome) {
			switch (outcome.status) {
				case "quarantined":
					quarantinedEvents++
					return
				case "ignored":
					ignoredEvents++
					return
				case "processed":
					processedEvents++
					if (outcome.alerts.length === 0) {
						eventsWithoutAlerts++
					}
					for (const alert of outcome.alerts) {
						detectedAlerts++
						alertsByRule[alert.ruleId] = (alertsByRule[alert.ruleId] ?? 0) + 1
					}
			}
		},

		summary(failedEvents: number) {
			return {
				receivedEvents,
				processedEvents,
				ignoredEvents,
				quarantinedEvents,
				eventsWithoutAlerts,
				detectedAlerts,
				alertsByRule,
				failedEvents,
			}
		},
	}
}
