import { parseCloudTrailEventType } from "../parsers/parseCloudTrailEvent"
import type { EventBridgeCloudTrailEvent, RawEventEnvelope } from "../types"

export const processEventBridgeCloudTrailEvent = (
	event: EventBridgeCloudTrailEvent,
): RawEventEnvelope[] => {
	const cloudTrailEvent = parseCloudTrailEventType(event)

	if (!cloudTrailEvent) {
		throw new Error(
			"Invalid EventBridge event: expected AWS API Call via CloudTrail",
		)
	}

	const ingestionTime = new Date().toISOString()

	const envelope: RawEventEnvelope = {
		eventId: cloudTrailEvent.eventID,
		ingestionTime,
		rawEvent: cloudTrailEvent,
	}

	return [envelope]
}
