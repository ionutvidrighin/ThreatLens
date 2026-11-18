import z from "zod"
import { CLOUD_TRAIL_EVENT } from "../constants"
import { OCSF_EVENT_CLASSES } from "../OCSFeventClasses"
import type { OCSFCloudTrailEvent } from "../ocsf/CloudTrail/validationSchemas"
import type { CommonRawEvent } from "../ocsf/commonRawEventSchema"

export const normalizeCloudTrailEventToOCSF = (
	rawMessage: CommonRawEvent,
): OCSFCloudTrailEvent => {
	const event = rawMessage.rawEvent

	if (!event || event.eventType !== CLOUD_TRAIL_EVENT) {
		throw new Error("Invalid CloudTrail event")
	}

	const timestamp = Date.parse(event.eventTime)

	if (!Number.isFinite(timestamp)) {
		throw new Error("Invalid event timestamp")
	}

	const API_ACTIVITY = OCSF_EVENT_CLASSES.applicationActivity.apiActivity

	const activityId = 99

	const sourceIp = event.sourceIPAddress

	const isIpAddress = z.union([z.ipv4(), z.ipv6()]).safeParse(sourceIp).success

	const accountId = event.userIdentity.accountId ?? event.recipientAccountId

	if (!accountId) {
		throw new Error("Missing AWS account ID")
	}

	return {
		class_uid: API_ACTIVITY.class_uid,
		category_uid: API_ACTIVITY.category_uid,

		activity_id: activityId,
		type_uid: API_ACTIVITY.class_uid * 100 + activityId,

		time: timestamp,
		severity_id: 1,

		status_id: event.errorCode
			? API_ACTIVITY.statuses.failure
			: API_ACTIVITY.statuses.success,

		metadata: {
			version: "1.3.0",
			product: {
				name: "ThreatLens",
				vendor_name: "ThreatLens",
			},
			original_event_uid: event.eventID,
		},

		actor: {
			user: {
				name:
					event.userIdentity.userName ??
					event.userIdentity.arn ??
					event.userIdentity.type,

				uid: event.userIdentity.principalId ?? event.userIdentity.arn,

				// Preserve the original CloudTrail identity classification.
				// This is a ThreatLens-specific extension.
				type: event.userIdentity.type,

				account: {
					uid: accountId,
				},
			},
		},

		api: {
			operation: event.eventName,
			service: {
				name: event.eventSource,
			},
		},

		cloud: {
			region: event.awsRegion,
			account: {
				uid: accountId,
			},
		},

		src_endpoint: isIpAddress ? { ip: sourceIp } : { name: sourceIp },

		requestParameters: {
			bucketName: event.requestParameters?.bucketName,
			Host: event.requestParameters?.Host,
		},

		// CloudTrail's { ARN, type } becomes OCSF's { uid, type }
		resources: event.resources?.map(({ ARN, type }) => ({ uid: ARN, type })),

		raw_data: JSON.stringify(event),
	}
}
