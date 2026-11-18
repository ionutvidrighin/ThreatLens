import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import {
	DynamoDBDocumentClient,
	PutCommand,
	QueryCommand,
} from "@aws-sdk/lib-dynamodb"
import {
	AUTH_FAILURES_DYNAMO_DB_TABLE,
	EVENT_DUPLICATE,
	EVENT_RETENTION_SECONDS,
	EVENT_STORED,
} from "../constants"
import type { AuthenticationFailure, OCSFAuthenticationEvent } from "../types"
import { isConditionalCheckFailure } from "../utils/common"

const dynamodb = DynamoDBDocumentClient.from(new DynamoDBClient({}))

/**
 * every failed login attempt is stored to Dynamo with its IP address.
 * in order to detect a potential attack, a query is performed on this table
 * to see how many attempts exist from a unique IP address and a unique username
 * within a time interval configured by the detection rule (ex. 5 minutes)
 */
export const storeAuthActivityFailure = async (
	event: OCSFAuthenticationEvent,
): Promise<string> => {
	const sourceIp = event?.src_endpoint?.ip
	const eventId = event?.metadata?.original_event_uid
	const eventDate = new Date(event.time)
	const username = event?.user?.name

	const eventKey = `${eventDate.toISOString()}#${eventId}`
	const expiresAt = Math.floor(Date.now() / 1000) + EVENT_RETENTION_SECONDS

	try {
		await dynamodb.send(
			new PutCommand({
				TableName: AUTH_FAILURES_DYNAMO_DB_TABLE,
				Item: {
					sourceIp,
					eventKey,
					eventId,
					eventTime: eventDate.toISOString(),
					username,
					expiresAt,
				},
				ConditionExpression: "attribute_not_exists(sourceIp)",
			}),
		)

		return EVENT_STORED // -> event stored to DynamoDB
	} catch (error) {
		if (isConditionalCheckFailure(error)) {
			return EVENT_DUPLICATE // -> event not stored to DynamoDB; it already exists
		}

		throw error
	}
}

export async function getRecentAuthFailuresByIp({
	sourceIp,
	windowStart,
	windowEnd,
}: {
	sourceIp: string
	windowStart: number
	windowEnd: number
}): Promise<AuthenticationFailure[]> {
	const failures: AuthenticationFailure[] = []

	let lastEvaluatedKey: Record<string, unknown> | undefined

	do {
		const result = await dynamodb.send(
			new QueryCommand({
				TableName: AUTH_FAILURES_DYNAMO_DB_TABLE,
				KeyConditionExpression:
					"sourceIp = :ip AND eventKey BETWEEN :start AND :end",
				ExpressionAttributeValues: {
					":ip": sourceIp,
					":start": `${new Date(Math.max(0, windowStart)).toISOString()}#`,
					":end": `${new Date(windowEnd).toISOString()}#\uffff`,
				},
				ProjectionExpression:
					"sourceIp, eventKey, eventId, eventTime, username",
				ConsistentRead: true,
				ExclusiveStartKey: lastEvaluatedKey,
			}),
		)

		failures.push(...((result.Items as AuthenticationFailure[]) ?? []))
		lastEvaluatedKey = result.LastEvaluatedKey
	} while (lastEvaluatedKey)

	return failures
}
