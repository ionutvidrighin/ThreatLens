import { z } from "zod"
import { HTTP_STATUS } from "@/constants"
import {
	detectionRuleSchema,
	fetchedRulesSchema,
	updateDetectionRuleSchema,
} from "./schemas/detectionRules.schemas"
import {
	ApiError,
	Get_Request,
	handleAPIerror,
	Patch_Request,
} from "./setup/client"
import { ENDPOINTS } from "./setup/endpoints"
import type { DetectionRule, UpdateDetectionRule } from "./types"

export const fetchRulesList = async (
	signal: AbortSignal,
): Promise<DetectionRule[]> => {
	let data: unknown

	const FETCH_RULES_LIST_ENDPOINT = ENDPOINTS.detectionRules.fetchRulesList

	try {
		data = await Get_Request(FETCH_RULES_LIST_ENDPOINT, {
			signal,
		})
	} catch (error) {
		handleAPIerror(error)
	}

	const result = fetchedRulesSchema.safeParse(data)
	if (!result.success)
		throw new ApiError(
			"The API returned an unexpected rule configuration.",
			HTTP_STATUS.UNPROCESSABLE_ENTITY,
		)

	return result.data.sort((a, b) => a.ruleId.localeCompare(b.ruleId))
}

export const updateDetectionRuleById = async (
	ruleId: string,
	update: UpdateDetectionRule,
): Promise<DetectionRule> => {
	let data: unknown
	const payload = updateDetectionRuleSchema.parse(update)

	const UPDATE_RULE_ENDPOINT =
		ENDPOINTS.detectionRules.updateDetectionRuleById(ruleId)

	try {
		data = await Patch_Request(UPDATE_RULE_ENDPOINT, payload)
	} catch (error) {
		handleAPIerror(error)
	}

	const result = z.object({ rule: detectionRuleSchema }).safeParse(data)
	if (!result.success || result.data.rule.ruleId !== ruleId) {
		throw new ApiError(
			"The update response could not be verified. Reload the rule before trying again.",
			HTTP_STATUS.UNPROCESSABLE_ENTITY,
		)
	}

	return result.data.rule
}
