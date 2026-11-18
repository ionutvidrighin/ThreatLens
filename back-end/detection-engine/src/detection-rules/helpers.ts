import {
	CLOUD_TAMPERING_OPERATIONS,
	CLOUDTRAIL_BUCKET_PREFIX,
	CLOUDTRAIL_SERVICE,
	S3_BUCKET_TAMPERING_OPERATIONS,
	S3_SERVICE,
} from "../constants"
import type {
	DetectionRule,
	OCSFAuthenticationEvent,
	OCSFCloudTrailEvent,
} from "../types"
import {
	AUTH_ACTIVITY_DETECTION_RULES,
	CLOUD_INFRA_DETECTION_RULES,
	type DetectionRuleId,
} from "./detectionRules"
import { OCSF_EVENT_CLASSES } from "./OCSFeventClasses"

const isLogonActivity = (event: OCSFAuthenticationEvent) =>
	event.class_uid ===
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication.class_uid &&
	event.activity_id ===
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication.activities
			.logon

export const isFailedAuthActivity = (event: OCSFAuthenticationEvent) =>
	isLogonActivity(event) &&
	event.status_id ===
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication.statuses
			.failure

export const isSuccessfulAuthActivity = (event: OCSFAuthenticationEvent) =>
	isLogonActivity(event) &&
	event.status_id ===
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication.statuses
			.success

/** True for failed-login events, the only events failure-based rules evaluate. */
export const isEligibleAuthEvent = (
	event: OCSFAuthenticationEvent,
	checkFor: "failedLogin" | "successLogin",
): boolean => {
	const OCSF_AUTH_CLASS =
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication

	if (checkFor === "successLogin") {
		const isEligible =
			event.class_uid === OCSF_AUTH_CLASS.class_uid &&
			event.activity_id === OCSF_AUTH_CLASS.activities.logon &&
			event.status_id === OCSF_AUTH_CLASS.statuses.success

		return isEligible
	}

	if (checkFor === "failedLogin") {
		const isEligible =
			event.class_uid === OCSF_AUTH_CLASS.class_uid &&
			event.activity_id === OCSF_AUTH_CLASS.activities.logon &&
			event.status_id === OCSF_AUTH_CLASS.statuses.failure

		return isEligible
	}

	return false
}

export const isEligileCloudTrailEvent = (event: OCSFCloudTrailEvent) => {
	const isCloudTrailLogsBucket =
		event.requestParameters?.bucketName?.startsWith(CLOUDTRAIL_BUCKET_PREFIX)

	const eventOperation = event.api.operation
	const eventServiceName = event.api.service.name

	if (eventServiceName === CLOUDTRAIL_SERVICE) {
		return CLOUD_TAMPERING_OPERATIONS.has(eventOperation)
	}

	if (eventServiceName === S3_SERVICE) {
		return (
			S3_BUCKET_TAMPERING_OPERATIONS.has(eventOperation) &&
			isCloudTrailLogsBucket
		)
	}

	return false
}

/** True when the configuration is usable by the rule identified by `ruleId`. */
export const validateDetectionRuleConfig = (
	config: DetectionRule,
	ruleId: DetectionRuleId,
): boolean => {
	const isAuthActivity = AUTH_ACTIVITY_DETECTION_RULES.some(
		(item) => item === ruleId,
	)
	const isCloudTrailActivity = CLOUD_INFRA_DETECTION_RULES.some(
		(item) => item === ruleId,
	)

	if (isAuthActivity) {
		return (
			Number.isInteger(config.threshold) &&
			(config.threshold ?? 0) >= 1 &&
			Number.isInteger(config.windowSeconds) &&
			(config.windowSeconds ?? 0) >= 1 &&
			config.ruleId === ruleId
		)
	}

	if (isCloudTrailActivity) {
		return config.ruleId === ruleId
	}

	return false
}
