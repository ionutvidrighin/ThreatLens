import { SendMessageBatchCommand, SQSClient } from "@aws-sdk/client-sqs"
import type { RawEventEnvelope } from "../types"

const sqs = new SQSClient({})

export const publishEventsToSQS = async (
	entries: RawEventEnvelope[],
	queueUrl: string,
): Promise<number> => {
	let forwardedEvents = 0

	// SQS SendMessageBatch supports up to 10 messages per request.
	for (let i = 0; i < entries.length; i += 10) {
		const batch = entries.slice(i, i + 10)

		const result = await sqs.send(
			new SendMessageBatchCommand({
				QueueUrl: queueUrl,
				Entries: batch.map((entry, index) => ({
					Id: String(index),
					MessageBody: JSON.stringify(entry),
				})),
			}),
		)

		const failed = result.Failed ?? []

		if (failed.length > 0) {
			console.error(
				JSON.stringify({
					component: "ThreatLensLogForwarder",
					failedMessages: failed.map((item) => ({
						id: item.Id,
						code: item.Code,
						message: item.Message,
					})),
				}),
			)

			throw new Error(`Failed to forward ${failed.length} SQS messages`)
		}

		forwardedEvents += batch.length
	}

	return forwardedEvents
}
