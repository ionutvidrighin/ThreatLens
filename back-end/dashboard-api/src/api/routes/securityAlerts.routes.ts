import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { HTTP_STATUS } from "@/constants"
import { HttpError } from "@/errors"
import { getSecurityAlerts } from "@/repositories/securityAlerts"
import { decodeCursor, encodeCursor } from "@/repositories/utils/commonHelpers"
import {
	filters,
	SECURITY_ALERTS_FILTERS,
} from "@/repositories/utils/securityAlertsHelpers"
import { AlertsFiltersQuerySchema } from "@/schemas/securityAlert.schema"
import { jsonResponse, parseOrThrow400 } from "../httpHelpers"

const DEFAULT_FILTER = "entityType"
const DEFAULT_FILTER_VALUE = "ALERT"

export const fetchSecurityAlerts = async (event: APIGatewayProxyEventV2) => {
	// Query param names the client can use as a filter. Only one at a time.
	const filtersList = Object.values(filters) as Array<keyof typeof filters>

	// validate the Query Params; if invalid, fallback to empty object {}
	const validQueryParams = parseOrThrow400(
		AlertsFiltersQuerySchema,
		event.queryStringParameters ?? {},
	)

	// which filter did the client use? At most one: a Query uses a single index
	const usedFilters = filtersList.filter(
		(name) => validQueryParams[name] !== undefined,
	)

	if (usedFilters.length > 1) {
		throw new HttpError(
			HTTP_STATUS.BAD_REQUEST,
			`Use only one filter at a time (got: ${usedFilters.join(", ")})`,
		)
	}

	// no filter passed -> defaults to (entityType = ALERT)
	const filterType = usedFilters[0] ?? DEFAULT_FILTER
	const filterValue = validQueryParams[filterType] ?? DEFAULT_FILTER_VALUE

	// validate cursor against the given filter schema
	// cursor comes as encoded string
	const validCursor = validQueryParams.cursor
		? decodeCursor(
				validQueryParams.cursor,
				SECURITY_ALERTS_FILTERS[filterType].validateSchema,
			)
		: undefined

	const { alerts: alertsList, lastEvaluatedKey } = await getSecurityAlerts({
		filterType,
		filterValue,
		limit: validQueryParams.limit,
		exclusiveStartKey: validCursor,
	})

	return jsonResponse({
		statusCode: HTTP_STATUS.OK,
		body: {
			alertsList,
			// only present when more alerts exist -> no cursor = hide "Load more"
			nextCursor: lastEvaluatedKey ? encodeCursor(lastEvaluatedKey) : undefined,
		},
	})
}
