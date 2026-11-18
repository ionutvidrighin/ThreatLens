import {
	AUTHENTICATION_EVENT,
	CLOUD_TRAIL_EVENT,
	INVALID_JSON,
	OCSF_SCHEMA_VALIDATION_FAILED,
	RAW_SCHEMA_VALIDATION_FAILED,
} from "./constants"
import { OCSFAuthenticationSchema } from "./ocsf/AuthenticationEvents/validationSchemas"
import { OCSFCloudTrailSchema } from "./ocsf/CloudTrail/validationSchemas"
import { CommonRawEventSchema } from "./ocsf/commonRawEventSchema"
import { parseJSONevent } from "./ocsf/helpers"
import { normalizeAuthEventToOCSF } from "./services/normalizeAuthEventService"
import { normalizeCloudTrailEventToOCSF } from "./services/normalizeCloudTrailEventService"
import type { EventNormalizationResult } from "./types"

export const validateAndNormalizeEvent = (
	rawMessage: string,
): EventNormalizationResult => {
	// 1. Parse the incoming JSON
	const parsedEvent = parseJSONevent(rawMessage)
	if (!parsedEvent.success) {
		return {
			success: false,
			reason: INVALID_JSON,
			validationErrors: [{ message: "Message body is not valid JSON" }],
		}
	}

	// 2. Validate the Raw Event agains the common schema
	const rawValidation = CommonRawEventSchema.safeParse(parsedEvent.data)

	if (!rawValidation.success) {
		return {
			success: false,
			reason: RAW_SCHEMA_VALIDATION_FAILED,
			validationErrors: rawValidation.error.issues,
		}
	}

	const rawEventType = rawValidation.data.rawEvent.eventType

	switch (rawEventType) {
		case AUTHENTICATION_EVENT: {
			// Normalize to OCSF Event of type Authentication
			const normalized = normalizeAuthEventToOCSF(rawValidation.data)

			// Validate OCSF Authentication Event
			const validation = OCSFAuthenticationSchema.safeParse(normalized)

			// Throw if validation unsuccessful
			if (!validation.success) {
				return {
					success: false,
					reason: OCSF_SCHEMA_VALIDATION_FAILED,
					validationErrors: validation.error.issues,
				}
			}

			return {
				success: true,
				data: validation.data,
			}
		}

		case CLOUD_TRAIL_EVENT: {
			// Normalize to OCSF Event of type Cloud Trail
			const normalized = normalizeCloudTrailEventToOCSF(rawValidation.data)

			// Validate OCSF Authentication Event
			const validation = OCSFCloudTrailSchema.safeParse(normalized)

			// Throw if validation unsuccessful
			if (!validation.success) {
				return {
					success: false,
					reason: OCSF_SCHEMA_VALIDATION_FAILED,
					validationErrors: validation.error.issues,
				}
			}

			return {
				success: true,
				data: validation.data,
			}
		}

		default: {
			return {
				success: false,
				reason: RAW_SCHEMA_VALIDATION_FAILED,
				validationErrors: [{ message: "Unsupported event type" }],
			}
		}
	}
}
