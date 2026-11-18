import { gunzipSync } from "node:zlib"
import type { CloudWatchPayload, CommonIncomingEvent } from "./types"

type ExtendedCommonIncomingEvent = CommonIncomingEvent & {
	awslogs: { data: string }
}

export const processCloudWatchEvent = (event: ExtendedCommonIncomingEvent) => {
	const compressed = Buffer.from(event.awslogs.data, "base64")
	const payload: CloudWatchPayload = JSON.parse(
		gunzipSync(compressed).toString("utf8"),
	)

	// CloudWatch may send control messages to validate delivery.
	if (payload.messageType === "CONTROL_MESSAGE") {
		return
	}

	if (payload.messageType !== "DATA_MESSAGE") {
		throw new Error(
			`Unexpected CloudWatch message type: ${payload.messageType}`,
		)
	}
}
