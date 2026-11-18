import z from "zod"
import { HTTP_STATUS } from "@/constants"
import { fetchedSecurityAlertsSchema } from "./schemas/securityAlerts.schemas"
import { ApiError, Get_Request, handleAPIerror } from "./setup/client"
import { ENDPOINTS } from "./setup/endpoints"
import type { SecurityAlert } from "./types"

export const fetchSecurityAlerts = async (
	signal: AbortSignal,
): Promise<SecurityAlert[]> => {
	let data: unknown

	const FETCH_ALERTS_ENDPOINT = ENDPOINTS.securityAlerts.fetchAlerts

	try {
		data = await Get_Request(FETCH_ALERTS_ENDPOINT, {
			signal,
		})
	} catch (error) {
		handleAPIerror(error)
	}

	const result = fetchedSecurityAlertsSchema.safeParse(data)
	if (!result.success)
		throw new ApiError(
			"The API returned an unexpected rule configuration.",
			HTTP_STATUS.UNPROCESSABLE_ENTITY,
		)

	return result.data.alertsList
}
