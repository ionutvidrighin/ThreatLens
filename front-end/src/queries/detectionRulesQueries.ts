import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
	fetchRulesList,
	updateDetectionRuleById,
} from "@/api/detectionRulesApi"
import { ApiError } from "@/api/setup/client"
import type { DetectionRule, UpdateDetectionRule } from "@/api/types"
import { HTTP_STATUS } from "@/constants"
import { useSession } from "@/hooks/useSession"
import { rulesErrorMessage } from "@/notifications"
import { QUERY_KEYS } from "./queriesKeys"

export const useGetRules = () => {
	return useQuery({
		queryKey: [QUERY_KEYS.detectionRulesGET],
		queryFn: ({ signal }) => fetchRulesList(signal),
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

export const useUpdateDetectionRule = () => {
	const session = useSession()
	const queryClient = useQueryClient()

	return useMutation({
		retry: false,
		mutationFn: async ({
			ruleId,
			updatedRule,
		}: {
			ruleId: string
			updatedRule: UpdateDetectionRule
		}) => {
			if (!session.isAuthenticated) {
				throw new Error("Sign in before updating a rule.")
			}

			if (!session.canEditRules) {
				throw new Error(
					"Your session does not have permission to update rules.",
				)
			}

			await queryClient.cancelQueries({
				queryKey: [QUERY_KEYS.detectionRulesGET],
			})

			return updateDetectionRuleById(ruleId, updatedRule)
		},

		onSuccess: (rule) => {
			queryClient.setQueryData<DetectionRule[]>(
				[QUERY_KEYS.detectionRulesGET],
				(oldData) => {
					return oldData?.map((item) =>
						item.ruleId === rule.ruleId ? rule : item,
					)
				},
			)

			queryClient.invalidateQueries({
				queryKey: [QUERY_KEYS.detectionRulesGET],
			})

			toast.success(
				"Rule updated. Detection changes can take up to 60 seconds.",
				{ id: "rule-update" },
			)
		},

		onError: (error) =>
			toast.error(rulesErrorMessage(error), { id: "rule-update" }),
	})
}
