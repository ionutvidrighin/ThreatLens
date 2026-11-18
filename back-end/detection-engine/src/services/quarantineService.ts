import { SendMessageCommand } from "@aws-sdk/client-sqs"
import { sqsClient } from "../clients/sqs"
import { config } from "../config"
import { COMPONENT_NAME, EVENT_QUARANTINED } from "../constants"
import type { QuarantineInput } from "../types"
import { logger } from "../utils/logger"

/** Single place that builds and publishes quarantine messages. */
export const quarantineEvent = async ({
	messageId,
	body,
	reason,
	validationErrors,
}: QuarantineInput): Promise<void> => {
	const quarantineMessage = {
		originalMessageId: messageId,
		rejectedAt: new Date().toISOString(),
		rejectedBy: COMPONENT_NAME,
		reason,
		validationErrors,
		originalEvent: body,
	}

	await sqsClient.send(
		new SendMessageCommand({
			QueueUrl: config.invalidEventsQueueUrl,
			MessageBody: JSON.stringify(quarantineMessage),
		}),
	)

	logger.warn(EVENT_QUARANTINED, { messageId, reason })
}
