import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb"
import type {
	GetSecurityAlertsParams,
	SecurityAlertsResponse,
	SecurityAlertType,
} from "@/schemas/securityAlert.schema"
import {
	createFilterMode,
	SECURITY_ALERTS_FILTERS,
} from "./utils/securityAlertsHelpers"

const dynamoDB = DynamoDBDocumentClient.from(new DynamoDBClient({}))

/**
 * Returns one page of alerts based on the filter used, newest first.
 */
export const getSecurityAlerts = async ({
	filterType,
	filterValue,
	limit,
	exclusiveStartKey,
}: GetSecurityAlertsParams): Promise<SecurityAlertsResponse> => {
	const TABLE_NAME = process.env.ALERTS_TABLE_NAME

	if (!TABLE_NAME) {
		throw new Error("ALERTS_TABLE_NAME env var is missing")
	}

	const command = new QueryCommand({
		TableName: TABLE_NAME,
		...createFilterMode(filterType, filterValue),
		ScanIndexForward: false, // newest first
		Limit: limit, // page size: 10, 20 etc. items
		ExclusiveStartKey: exclusiveStartKey, // where the previous page ended
	})

	const response = await dynamoDB.send(command)
	const hasMorePagesToQuery = response.LastEvaluatedKey

	// LastEvaluatedKey only exists when more pages remain; on the last page it is
	// undefined and must not be parsed (that throws a ZodError -> 500)
	const validateCursorPosition = hasMorePagesToQuery
		? SECURITY_ALERTS_FILTERS[filterType].validateSchema.parse(
				hasMorePagesToQuery,
			)
		: undefined

	const alertsList = (response.Items ?? []).map((alert) => alert)

	return {
		alerts: alertsList as SecurityAlertType[],
		lastEvaluatedKey: validateCursorPosition,
	}
}
