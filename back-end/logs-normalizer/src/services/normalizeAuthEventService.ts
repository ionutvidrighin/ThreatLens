import { AUTHENTICATION_EVENT } from "../constants"
import { OCSF_EVENT_CLASSES } from "../OCSFeventClasses"
import type { OCSFAuthenticationEvent } from "../ocsf/AuthenticationEvents/validationSchemas"
import type { CommonRawEvent } from "../ocsf/commonRawEventSchema"

export const normalizeAuthEventToOCSF = (
	rawMessage: CommonRawEvent,
): OCSFAuthenticationEvent => {
	const event = rawMessage.rawEvent

	if (
		!event ||
		event.eventType !== AUTHENTICATION_EVENT ||
		typeof event.eventId !== "string" ||
		typeof event.username !== "string" ||
		typeof event.sourceIp !== "string" ||
		!["success", "failure"].includes(event.outcome)
	) {
		throw new Error("Invalid authentication event")
	}

	const timestamp = Date.parse(event.eventTime)

	if (!Number.isFinite(timestamp)) {
		throw new Error("Invalid event timestamp")
	}

	const AUTH_ACTIVITY =
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication

	return {
		class_uid: AUTH_ACTIVITY.class_uid,
		category_uid: AUTH_ACTIVITY.category_uid,
		activity_id: AUTH_ACTIVITY.activities.logon,
		type_uid: AUTH_ACTIVITY.class_uid * 100 + AUTH_ACTIVITY.activities.logon,
		time: timestamp,
		severity_id: 1,
		status_id:
			event.outcome === "success"
				? AUTH_ACTIVITY.statuses.success
				: AUTH_ACTIVITY.statuses.failure,
		metadata: {
			version: "1.3.0",
			product: {
				name: "ThreatLens",
				vendor_name: "ThreatLens",
			},
			original_event_uid: event.eventId,
		},
		user: {
			name: event.username,
		},
		src_endpoint: {
			ip: event.sourceIp,
		},
		observables: [
			{
				name: "username",
				type_id: 4,
				value: event.username,
			},
		],
		raw_data: JSON.stringify(rawMessage),
	}
}
