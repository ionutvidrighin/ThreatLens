import { INVALID_OCSF_SCHEMA } from "../constants"
import {
	isFailedAuthActivity,
	isSuccessfulAuthActivity,
} from "../detection-rules/helpers"
import { storeAuthActivityFailure } from "../repositories/authFailures"
import { OCSFAuthenticationSchema } from "../schemas/ocsfAuthentication.schema"
import { evaluateAuthDetectionRules } from "../services/detectionRulesEvaluationService"
import { quarantineEvent } from "../services/quarantineService"
import type { ProcessedEventOutcome } from "../types"

export const processAuthEvent = async (
	messageId: string,
	body: string,
	validJSONevent: unknown,
): Promise<ProcessedEventOutcome> => {
	const validatedEvent = OCSFAuthenticationSchema.safeParse(validJSONevent)

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

	const isFailedLogin = isFailedAuthActivity(eventData)

	// Only logon attempts matter. Successful logins are evaluated (for other detection rules
	// such as success-login-after-failures) but never stored as failures.
	if (!isFailedLogin && !isSuccessfulAuthActivity(eventData)) {
		return { status: "ignored" }
	}

	if (isFailedLogin) {
		await storeAuthActivityFailure(eventData)
	}

	const alerts = await evaluateAuthDetectionRules(eventData)
	return { status: "processed", alerts }
}
