import { SendMessageCommand, SQSClient } from "@aws-sdk/client-sqs"

import type { SQSBatchResponse, SQSEvent, SQSHandler } from "aws-lambda"
import { COMPONENT_NAME } from "./constants"
import { validateAndNormalizeEvent } from "./validateAndNormalizeEvent"

const amazonSimpleQueueService = new SQSClient({})

const normalizedQueueUrl = process.env.NORMALIZED_EVENTS_SQS_FIFO_QUEUE_URL
const quarantineQueueUrl = process.env.QUARANTINE_SQS_QUEUE_URL

export const handler: SQSHandler = async (
	event: SQSEvent,
): Promise<SQSBatchResponse> => {
	if (!normalizedQueueUrl) {
		throw new Error(
			"NORMALIZED_EVENTS_SQS_FIFO_QUEUE_URL is missing. Check env var.",
		)
	}

	const batchItemFailures: Array<{
		itemIdentifier: string
	}> = []

	let normalizedEvents = 0

	const records = event.Records
	for (const sqsRecord of records) {
		try {
			const result = validateAndNormalizeEvent(sqsRecord.body)

			if (!result.success) {
				const quarantineMessage = {
					originalMessageId: sqsRecord.messageId,
					rejectedAt: new Date().toISOString(),
					rejectedBy: COMPONENT_NAME,
					reason: result.reason,
					validationErrors: result.validationErrors,
					originalEvent: sqsRecord.body,
				}

				// quarantine the event
				await amazonSimpleQueueService.send(
					new SendMessageCommand({
						QueueUrl: quarantineQueueUrl,
						MessageBody: JSON.stringify(quarantineMessage),
					}),
				)

				continue
			}

			const normalizedEvent = result.data
			const messageGroupId =
				normalizedEvent.src_endpoint?.ip || "threatlens-unknown-source"

			await amazonSimpleQueueService.send(
				new SendMessageCommand({
					QueueUrl: normalizedQueueUrl,
					MessageBody: JSON.stringify(normalizedEvent),
					MessageGroupId: messageGroupId,
					MessageDeduplicationId: normalizedEvent.metadata.original_event_uid,
				}),
			)

			normalizedEvents++
		} catch (error) {
			console.error(
				JSON.stringify({
					component: COMPONENT_NAME,
					messageId: sqsRecord.messageId,
					error: error instanceof Error ? error.message : "Unknown error",
				}),
			)

			batchItemFailures.push({
				itemIdentifier: sqsRecord.messageId,
			})
		}
	}

	// show amount of processed events in CloudWatch logs
	console.log(
		JSON.stringify({
			details: "Amount of processed events",
			component: COMPONENT_NAME,
			receivedEvents: event.Records.length,
			normalizedEvents,
			failedEvents: batchItemFailures.length,
		}),
	)

	return {
		batchItemFailures,
	}
}
