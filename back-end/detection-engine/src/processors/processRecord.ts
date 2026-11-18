import type { SQSRecord } from "aws-lambda"
import { z } from "zod"
import { INVALID_JSON, INVALID_OCSF_SCHEMA } from "../constants"
import { OCSF_EVENT_CLASSES } from "../detection-rules/OCSFeventClasses"
import { quarantineEvent } from "../services/quarantineService"
import type { ProcessedEventOutcome } from "../types"
import { parseOCSFevent } from "../utils/parseOCSFevent"
import { processAuthEvent } from "./processAuthenticationEvent"
import { processCloudTrailEvent } from "./processCloudTrailEvent"

const OCSFEventClassifierSchema = z.object({
	class_uid: z.number().int(),
})

/**
 * Run one SQS record through parse, validate, filter, store and detect.
 * Expected outcomes are returned; unexpected failures are thrown so the
 * batch loop can apply its retry policy.
 */
export const processRecord = async (
	record: SQSRecord,
): Promise<ProcessedEventOutcome> => {
	const { messageId, body } = record

	const parsedJSONevent = parseOCSFevent(body)

	if (!parsedJSONevent.success) {
		await quarantineEvent({
			messageId,
			body,
			reason: INVALID_JSON,
			validationErrors: [{ message: "SQS message body is not valid JSON" }],
		})
		return { status: "quarantined" }
	}

	const classification = OCSFEventClassifierSchema.safeParse(
		parsedJSONevent.data,
	)

	if (!classification.success) {
		await quarantineEvent({
			messageId,
			body,
			reason: INVALID_OCSF_SCHEMA,
			validationErrors: classification.error.issues,
		})
		return { status: "quarantined" }
	}

	const AUTH_ACTIVITY =
		OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication
	const API_ACTIVITY = OCSF_EVENT_CLASSES.applicationActivity.apiActivity

	switch (classification.data.class_uid) {
		case AUTH_ACTIVITY.class_uid: {
			return processAuthEvent(messageId, body, parsedJSONevent.data)
		}

		case API_ACTIVITY.class_uid: {
			return processCloudTrailEvent(messageId, body, parsedJSONevent.data)
		}

		default: {
			await quarantineEvent({
				messageId,
				body,
				reason: INVALID_OCSF_SCHEMA,
				validationErrors: [
					{
						message: `Unsupported OCSF event class: ${classification.data.class_uid}`,
					},
				],
			})

			return { status: "quarantined" }
		}
	}
}
