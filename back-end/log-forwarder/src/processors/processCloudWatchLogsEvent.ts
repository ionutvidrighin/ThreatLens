import { gunzipSync } from "node:zlib"
import type { CloudWatchLogsEvent } from "aws-lambda"
import { parseAuthenticationEventType } from "../parsers/parseAuthenticationEvent"
import type { CloudWatchPayload, RawEventEnvelope } from "../types"

export const processCloudWatchLogsEvent = (
	event: CloudWatchLogsEvent,
): RawEventEnvelope[] => {
	if (!event?.awslogs?.data) {
		throw new Error(
			"Invalid event: expected CloudWatch Logs subscription payload",
		)
	}

	// Decode the Base64-encoded, GZIP-compressed CloudWatch payload.
	const compressed = Buffer.from(event.awslogs.data, "base64")

	const payload: CloudWatchPayload = JSON.parse(
		gunzipSync(compressed).toString("utf8"),
	)

	// CloudWatch may send control messages to validate delivery.
	if (payload.messageType === "CONTROL_MESSAGE") {
		return []
	}

	if (payload.messageType !== "DATA_MESSAGE") {
		throw new Error(
			`Unexpected CloudWatch message type: ${payload.messageType}`,
		)
	}

	// Generate a consistent ingestion timestamp for the batch.
	const ingestionTime = new Date().toISOString()

	// Extract authentication events and construct their raw envelopes.
	const validAuthEvents: RawEventEnvelope[] = (payload.logEvents ?? []).flatMap(
		(log) => {
			const authEvent = parseAuthenticationEventType(log.message)

			if (!authEvent) {
				return []
			}

			return [
				{
					eventId: authEvent.eventId,
					sourceLogEventId: log.id,
					sourceLogGroup: payload.logGroup,
					sourceLogStream: payload.logStream,
					ingestionTime,
					rawEvent: authEvent,
				},
			]
		},
	)

	return validAuthEvents
}
