import {
	ConditionalCheckFailedException,
	DynamoDBClient,
} from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb"
import { EVENT_DUPLICATE, EVENT_STORED } from "../constants"
import type { SecurityAlert } from "../types"

const dynamodb = DynamoDBDocumentClient.from(new DynamoDBClient({}))

export async function storeSecurityAlert(
	alert: SecurityAlert,
): Promise<typeof EVENT_STORED | typeof EVENT_DUPLICATE> {
	const SECURITY_ALERTS_DB_TABLE = process.env.SECURITY_ALERTS_DYNAMO_DB_TABLE

	if (!SECURITY_ALERTS_DB_TABLE) {
		throw new Error("Security alerts DynamoDB table is not configured")
	}

	try {
		await dynamodb.send(
			new PutCommand({
				TableName: SECURITY_ALERTS_DB_TABLE,
				Item: alert,
				ConditionExpression: "attribute_not_exists(alertId)",
			}),
		)

		return EVENT_STORED
	} catch (error) {
		if (error instanceof ConditionalCheckFailedException) {
			return EVENT_DUPLICATE
		}

		throw error
	}
}
