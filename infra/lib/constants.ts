export const CONSTRUCT_IDS = {
	dynamoDBtables: {
		// ID of the DynamoDBTables construct (the group that holds every table)
		id: "DynamoTables",

		// IDs of each DynamoDB table inside the group
		detectionRulesTable: "DetectionRulesTable",
		authFailuresTable: "AuthenticationFailuresTable",
		securityAlertsTable: "SecurityAlertsTable",
		securityAlertsGlobalIndexes: [
			"ruleId",
			"entityType",
			"sourceIp",
			"severity",
		],
	},
	sqsQueues: {
		// ID of the SQS construct (the group that holds every queue)
		id: "ThreatLensSQS",

		// IDs of the each SQS queue the group
		raw_logs_q_id: "RawLogsQ",
		raw_logs_dead_letter_q_id: "RawLogsDLQ",
		normalized_logs_fifo_q_id: "LogsNormalizedFIFOQ",
		normalized_logs_dead_letter_q_id: "LogsNormalizedDLQ",
		quarantine_normalized_logs_q_id: "QuarantineNormalizedQ",
		quarantine_ocsf_logs_q_id: "QuarantineOCSFlogsQ",
	},
} as const
