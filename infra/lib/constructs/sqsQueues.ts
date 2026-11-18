import * as sqs from "aws-cdk-lib/aws-sqs"
import * as cdk from "aws-cdk-lib/core"
import { Construct } from "constructs"
import { CONSTRUCT_IDS } from "../constants"

export class SQSqueues extends Construct {
	public readonly rawLogsQueue: sqs.Queue
	public readonly logsNormalizerFIFOqueue: sqs.Queue
	public readonly quarantineNormalizedLogsQueue: sqs.Queue
	public readonly quarantineOCSFlogsQueue: sqs.Queue

	constructor(scope: Construct, id: string) {
		super(scope, id)

		const rawLogsDLQ = new sqs.Queue(
			this,
			CONSTRUCT_IDS.sqsQueues.raw_logs_dead_letter_q_id,
			{
				fifo: false,
				retentionPeriod: cdk.Duration.days(14),
			},
		)

		this.rawLogsQueue = new sqs.Queue(
			this,
			CONSTRUCT_IDS.sqsQueues.raw_logs_q_id,
			{
				fifo: false,
				visibilityTimeout: cdk.Duration.minutes(3),
				retentionPeriod: cdk.Duration.days(4),
				deadLetterQueue: {
					queue: rawLogsDLQ,
					maxReceiveCount: 4,
				},
			},
		)

		/** SQS Queues used by the  */
		const logsNormalizerDLQ = new sqs.Queue(
			this,
			CONSTRUCT_IDS.sqsQueues.normalized_logs_dead_letter_q_id,
			{
				fifo: true,
				retentionPeriod: cdk.Duration.days(14),
			},
		)

		this.logsNormalizerFIFOqueue = new sqs.Queue(
			this,
			CONSTRUCT_IDS.sqsQueues.normalized_logs_fifo_q_id,
			{
				fifo: true,
				visibilityTimeout: cdk.Duration.minutes(3),
				retentionPeriod: cdk.Duration.days(4),
				deadLetterQueue: {
					queue: logsNormalizerDLQ,
					maxReceiveCount: 5,
				},
			},
		)

		this.quarantineNormalizedLogsQueue = new sqs.Queue(
			this,
			CONSTRUCT_IDS.sqsQueues.quarantine_normalized_logs_q_id,
			{
				fifo: false,
				visibilityTimeout: cdk.Duration.seconds(30),
				retentionPeriod: cdk.Duration.days(14),
			},
		)

		this.quarantineOCSFlogsQueue = new sqs.Queue(
			this,
			CONSTRUCT_IDS.sqsQueues.quarantine_ocsf_logs_q_id,
			{
				fifo: false,
				visibilityTimeout: cdk.Duration.seconds(30),
				retentionPeriod: cdk.Duration.days(14),
			},
		)
	}
}
