import { AUTHENTICATION_EVENT } from "../constants"
import type { AuthenticationEventType } from "../types"

/**
 * Extracts an authentication event from a CloudWatch log message.
 *
 * Supports:
 * 1. Plain JSON messages.
 * 2. Lambda-prefixed messages containing timestamp, request ID,
 *    log level, and JSON.
 */
export const parseAuthenticationEventType = (
	message: string,
): AuthenticationEventType | null => {
	const jsonStart = message.indexOf("{")

	if (jsonStart === -1) {
		return null
	}

	try {
		const parsedEvent: unknown = JSON.parse(message.slice(jsonStart).trim())

		if (
			typeof parsedEvent !== "object" ||
			parsedEvent === null ||
			Array.isArray(parsedEvent) ||
			!("eventType" in parsedEvent) ||
			parsedEvent.eventType !== AUTHENTICATION_EVENT
		) {
			return null
		}

		return parsedEvent as AuthenticationEventType
	} catch {
		return null
	}
}
