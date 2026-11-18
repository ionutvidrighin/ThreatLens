import { useQuery } from "@tanstack/react-query"
import { fetchSecurityAlerts } from "@/api/securityAlertsApi"
import { ApiError } from "@/api/setup/client"
import { HTTP_STATUS } from "@/constants"
import { QUERY_KEYS } from "./queriesKeys"

export const useGetSecurityAlerts = () => {
	return useQuery({
		queryKey: [QUERY_KEYS.securityAlertsGET],
		queryFn: ({ signal }) => fetchSecurityAlerts(signal),
		retry: (failureCount, error) => {
			if (
				error instanceof ApiError &&
				error.status < HTTP_STATUS.INTERNAL_SERVER_ERROR &&
				error.status !== HTTP_STATUS.TOO_MANY_REQUESTS
			)
				return false
			return failureCount < 2
		},
	})
}
