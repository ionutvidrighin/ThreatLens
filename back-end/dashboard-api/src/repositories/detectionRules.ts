import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import {
	DynamoDBDocumentClient,
	ScanCommand,
	UpdateCommand,
} from "@aws-sdk/lib-dynamodb"
import { RuleUpdateConflictError } from "@/errors"
import {
	DetectionRuleSchema,
	type DetectionRuleType,
} from "@/schemas/detectionRule.schema"
import { DYNAMODB_ERROR_CODE } from "../constants"
import {
	DetectionRuleUpdateSchema,
	type DetectionRuleUpdateType,
} from "../schemas/detectionRuleUpdate.schema"
import { buildRuleUpdateExpression } from "./utils/commonHelpers"
import type { DetectionRuleId } from "./utils/detectionRulesHelpers"

const dynamodb = DynamoDBDocumentClient.from(new DynamoDBClient({}))

export const getDetectionRules = async (): Promise<DetectionRuleType[]> => {
	const TABLE_NAME = process.env.DETECTION_RULES_TABLE_NAME

	if (!TABLE_NAME) {
		throw new Error("DETECTION_RULES_TABLE_NAME env var is missing")
	}

	const response = await dynamodb.send(
		new ScanCommand({ TableName: TABLE_NAME, ConsistentRead: true }),
	)

	return (response.Items ?? []).map((item) => DetectionRuleSchema.parse(item))
}

export const updateDetectionRule = async (
	ruleId: DetectionRuleId,
	payload: DetectionRuleUpdateType,
): Promise<DetectionRuleType> => {
	const TABLE_NAME = process.env.DETECTION_RULES_TABLE_NAME

	if (!TABLE_NAME) {
		throw new Error("DETECTION_RULES_TABLE_NAME env var is missing")
	}

	const { previouslyUpdatedAt, ...changes } =
		DetectionRuleUpdateSchema.parse(payload)

	const command = new UpdateCommand({
		TableName: TABLE_NAME,
		Key: { ruleId },
		// UpdateExpression, attribute names/values and the optimistic-lock condition
		// (see buildRuleUpdateExpression for a full example of the resulting command)
		...buildRuleUpdateExpression(ruleId, changes, previouslyUpdatedAt),
		// Return the item as stored after the update, including the new updatedAt
		ReturnValues: "ALL_NEW",
	})

	try {
		const result = await dynamodb.send(command)
		return DetectionRuleSchema.parse(result.Attributes)
	} catch (error) {
		if (
			error instanceof Error &&
			error.name === DYNAMODB_ERROR_CODE.CONDITIONAL_CHECK_FAILED
		) {
			throw new RuleUpdateConflictError(
				"Rule changed or no longer exists; reload before retrying",
			)
		}
		throw error
	}
}
