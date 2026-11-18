import {
	EntityTypeFilterSchema,
	type FilterType,
	RuleIdFilterSchema,
	SeverityFilterSchema,
	SourceIpFilterSchema,
} from "@/schemas/securityAlert.schema"
import { DETECTION_RULE_IDS } from "./detectionRulesHelpers"

export const filters = {
	ruleId: "ruleId",
	entityType: "entityType",
	sourceIp: "sourceIp",
	severity: "severity",
}

/* all queries filtering are ordered by date because
 *  "createdAt" table head is set as sortKey on AWS console
 *  which allows Dynamo to order the data by "createdAt"
 */
export const SECURITY_ALERTS_FILTERS = {
	[filters.ruleId]: {
		filterName: "query-by-ruleId",
		primaryKey: "ruleId", // column header in DynamoDB
		valuePlaceholder: ":ruleIdValue",
		validateSchema: RuleIdFilterSchema,
	},
	[filters.entityType]: {
		filterName: "query-by-entityType",
		primaryKey: "entityType", // column header in DynamoDB
		valuePlaceholder: ":entityTypeValue",
		validateSchema: EntityTypeFilterSchema,
	},
	[filters.sourceIp]: {
		filterName: "query-by-sourceIp",
		primaryKey: "sourceIp", // column header in DynamoDB
		valuePlaceholder: ":sourceIpValue",
		validateSchema: SourceIpFilterSchema,
	},
	[filters.severity]: {
		filterName: "query-by-severity",
		primaryKey: "severity", // column header in DynamoDB
		valuePlaceholder: ":severityValue",
		validateSchema: SeverityFilterSchema,
	},
} as const

/**
 * by default, we dont query the whole DynamoDB because it's expensive (there could be thousands of entries)
 * therefore, we set a default filter type to query data:
 * -> "entityType", which maps to the SECURITY_ALERTS_FILTERS object entries
 * -> and "ALERT", which is a value of "entityType" table column in DynamoDB
 */
const defaultFilter = Object.keys(
	SECURITY_ALERTS_FILTERS,
)[0] as keyof typeof SECURITY_ALERTS_FILTERS

/**
 * @param type defines how we're querying data from Dynamo: by "createdAt", by "sourceIp", by "severity" etc
 * @param valueFilter different table columns in "threatlens-security-alerts" table
 * like: ALERT -> "entityType" or high -> "severity"; these values come from the client
 * @returns the built conditions for the query as object of form
 *   {
 *     IndexName: "index" -> the given Global index set on AWS console DynamoDB
 *     KeyConditionExpression: "primaryKey = :primaryKeyValuePlaceholder" -> table head and a placeholder for the values the column has
 *     ExpressionAttributeValues: { ":primaryKeyValuePlaceholder": "valueFilter" } -> the placeholder for the values the column has and the actual VALUE we're querying
 *   }
 */
export const createFilterMode = (
	filter: FilterType = defaultFilter, // default filter -> ruleId
	filterValue: string = DETECTION_RULE_IDS[0], // default ruleId value as filtering
) => {
	const filterType = SECURITY_ALERTS_FILTERS[filter]

	return {
		IndexName: filterType.filterName,
		KeyConditionExpression: `${filterType.primaryKey} = ${filterType.valuePlaceholder}`,
		ExpressionAttributeValues: {
			[filterType.valuePlaceholder]: filterValue,
		},
	}
}
