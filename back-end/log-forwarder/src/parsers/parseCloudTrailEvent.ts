import type { CloudTrailEventType, CommonIncomingEvent } from "../types"

export const parseCloudTrailEventType = (
	event: CommonIncomingEvent,
): CloudTrailEventType | null => {
	if (!("detail-type" in event)) {
		return null
	}

	if (
		event["detail-type"] !== "AWS API Call via CloudTrail" ||
		event.detail === null ||
		typeof event.detail !== "object" ||
		Array.isArray(event.detail)
	) {
		return null
	}

	return event.detail
}
