import type {
	SQSBatchItemFailure,
	SQSBatchResponse,
	SQSEvent,
} from "aws-lambda"
import { createBatchMetrics } from "./pipeline/batchMetrics"
import { processRecord } from "./processors/processRecord"
import { logger } from "./utils/logger"

export const handler = async (event: SQSEvent): Promise<SQSBatchResponse> => {
	const records = event.Records
	const metrics = createBatchMetrics(records.length)
	const batchItemFailures: SQSBatchItemFailure[] = []

	for (const [index, record] of records.entries()) {
		try {
			metrics.record(await processRecord(record))
		} catch (error) {
			logger.error("EVENT_PROCESSING_FAILED", {
				messageId: record.messageId,
				error: error instanceof Error ? error.message : "Unknown error",
			})

			// Preserve FIFO ordering: retry the failed record and all after it.
			batchItemFailures.push(
				...records.slice(index).map((r) => ({ itemIdentifier: r.messageId })),
			)
			break
		}
	}

	logger.info("BATCH_SUMMARY", metrics.summary(batchItemFailures.length))

	return { batchItemFailures }
}
