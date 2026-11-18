export const CONSTRUCT_IDS = {
	dynamoDBtables: {
		// ID of the DynamoDBTables construct (the group that holds every table)
		id: "DynamoTables",
		// ID of the detection rules table inside that group
		detectionRulesTable: "DetectionRulesTable",
	},
} as const
