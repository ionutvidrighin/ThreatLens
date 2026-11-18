import { INVALID_OCSF_SCHEMA } from "../constants"
import { OCSFCloudTrailSchema } from "../schemas/ocsfCloudTrail.schema"
import { evaluateCloudTrailRules } from "../services/detectionRulesEvaluationService"
import { quarantineEvent } from "../services/quarantineService"
import type { ProcessedEventOutcome } from "../types"

export const processCloudTrailEvent = async (
	messageId: string,
	body: string,
	validJSONevent: unknown,
): Promise<ProcessedEventOutcome> => {
	const validatedEvent = OCSFCloudTrailSchema.safeParse(validJSONevent)

	if (!validatedEvent.success) {
		await quarantineEvent({
			messageId,
			body,
			reason: INVALID_OCSF_SCHEMA,
			validationErrors: validatedEvent.error.issues,
		})
		return { status: "quarantined" }
	}

	const eventData = validatedEvent.data

	console.log(
		JSON.stringify({
			component: "ThreatLensDetectionEngine",
			action: "CLOUDTRAIL_EVENT_VALIDATED",
			eventId: eventData.metadata.original_event_uid,
			operation: eventData.api.operation,
			service: eventData.api.service.name,
		}),
	)

	const alerts = await evaluateCloudTrailRules(eventData)
	return { status: "processed", alerts }
}
