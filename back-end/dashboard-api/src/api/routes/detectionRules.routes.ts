import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { HTTP_STATUS } from "@/constants"
import { HttpError, RuleNotFoundError } from "@/errors"
import {
	getDetectionRules,
	updateDetectionRule,
} from "@/repositories/detectionRules"
import { isDetectionRuleId } from "@/repositories/utils/detectionRulesHelpers"
import { DetectionRuleUpdateSchema } from "@/schemas/detectionRuleUpdate.schema"
import { jsonResponse, parseJsonBody, parseOrThrow400 } from "../httpHelpers"

export const fetchDetectionRules = async () => {
	const detectionRulesList = await getDetectionRules()
	return jsonResponse({ statusCode: HTTP_STATUS.OK, body: detectionRulesList })
}

export const updateSingleDetectionRule = async (
	event: APIGatewayProxyEventV2,
) => {
	// get the ruleId from the route params
	const ruleId = event.pathParameters?.ruleId
	if (!ruleId) {
		throw new HttpError(
			HTTP_STATUS.BAD_REQUEST,
			"Missing rule ID in the route params",
		)
	}
	if (!isDetectionRuleId(ruleId)) {
		throw new RuleNotFoundError("The given Rule ID does not exist")
	}

	// read the JSON body (throws 400 if missing or malformed)
	const payload = parseJsonBody(event)

	// validate the body content against the Zod Schema for the Detection Rule Update
	const validPayload = parseOrThrow400(DetectionRuleUpdateSchema, payload)

	// perform the actual Rule Update
	const updatedRuleResponse = await updateDetectionRule(ruleId, validPayload)
	return jsonResponse({
		statusCode: HTTP_STATUS.OK,
		body: { rule: updatedRuleResponse },
	})
}
