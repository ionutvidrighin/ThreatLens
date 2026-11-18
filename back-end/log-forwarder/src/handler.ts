import { processCloudWatchLogsEvent } from "./processors/processCloudWatchLogsEvent"
import { processEventBridgeCloudTrailEvent } from "./processors/processEventBridgeCloudTrailEvent"
import { publishEventsToSQS } from "./services/publishEventsToSQS"
import type {
	CommonIncomingEvent,
	EventSource,
	RawEventEnvelope,
} from "./types"

const queueUrl = process.env.RAW_AUTH_QUEUE_URL

/**
 * Receives events from CloudWatch Logs or EventBridge,
 * constructs raw event envelopes, and forwards them to SQS.
 */
export const handler = async (event: CommonIncomingEvent): Promise<void> => {
	if (!queueUrl) {
		throw new Error("RAW_AUTH_QUEUE_URL env var is missing.")
	}

	let entries: RawEventEnvelope[]
	let eventSource: EventSource

	if ("awslogs" in event) {
		entries = processCloudWatchLogsEvent(event)
		eventSource = "CloudWatchLogs"
	} else if (
		"detail-type" in event &&
		event["detail-type"] === "AWS API Call via CloudTrail"
	) {
		entries = processEventBridgeCloudTrailEvent(event)
		eventSource = "EventBridge"
	} else {
		throw new Error("Unsupported event source")
	}

	const forwardedEvents = await publishEventsToSQS(entries, queueUrl)

	console.log(
		JSON.stringify({
			component: "ThreatLensLogForwarder",
			eventSource,
			processedEvents: entries.length,
			forwardedEvents,
		}),
	)
}
