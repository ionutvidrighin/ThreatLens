import type { AUTHENTICATION_EVENT, CLOUD_TRAIL_EVENT } from "./constants"
import type { OCSFAuthenticationEvent } from "./ocsf/AuthenticationEvents/validationSchemas"
import type { OCSFCloudTrailEvent } from "./ocsf/CloudTrail/validationSchemas"

export type EventType = typeof AUTHENTICATION_EVENT | typeof CLOUD_TRAIL_EVENT

export type AuthEventNormalizationResult =
	| {
			success: true
			data: OCSFAuthenticationEvent
	  }
	| {
			success: false
			reason: string
			validationErrors: unknown[]
	  }

export type CloudTrailEventNormalizationResult =
	| {
			success: true
			data: OCSFCloudTrailEvent
	  }
	| {
			success: false
			reason: string
			validationErrors: unknown[]
	  }

export type NormalizedEvent = OCSFAuthenticationEvent | OCSFCloudTrailEvent

export type EventNormalizationResult =
	| AuthEventNormalizationResult
	| CloudTrailEventNormalizationResult
