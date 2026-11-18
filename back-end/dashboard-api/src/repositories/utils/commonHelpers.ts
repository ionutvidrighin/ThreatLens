import type { ZodType, z } from "zod"
import { HTTP_STATUS } from "@/constants"
import { HttpError } from "@/errors"
import type { DetectionRuleUpdateType } from "@/schemas/detectionRuleUpdate.schema"
import {
	DETECTION_RULE_IDS,
	DETECTION_RULES,
	type DetectionRuleId,
} from "./detectionRulesHelpers"

/**
 * DynamoDB `LastEvaluatedKey` (object) -> opaque cursor string for the client.
 * base64url (not plain base64) so it is safe inside a query string:
 * no `+`, `/` or `=` characters.
 */
export const encodeCursor = (key: object): string =>
	Buffer.from(JSON.stringify(key), "utf8").toString("base64url")

/**
 * Cursor string from the client -> validated key object for `ExclusiveStartKey`.
 * The cursor comes from the client, so it can be anything: it is validated with
 * the given schema and any failure becomes a 400 (never a 500).
 */
export const decodeCursor = <SchemaType extends ZodType>(
	cursor: string,
	schema: SchemaType,
): z.infer<SchemaType> => {
	let decoded: unknown
	try {
		decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"))
	} catch {
		throw new HttpError(HTTP_STATUS.BAD_REQUEST, "Invalid cursor")
	}

	const result = schema.safeParse(decoded)
	if (!result.success) {
		throw new HttpError(HTTP_STATUS.BAD_REQUEST, "Invalid cursor")
	}
	return result.data
}

type RuleChanges = Omit<DetectionRuleUpdateType, "previouslyUpdatedAt">

type UpdateExpressionParts = {
	UpdateExpression: string
	ExpressionAttributeNames: Record<string, string>
	ExpressionAttributeValues: Record<string, unknown>
	ConditionExpression: string
}

/**
 * Builds the pieces of a DynamoDB UpdateCommand for a partial rule update.
 * Pure function: no AWS calls, so it can be unit tested on its own.
 *
 * Example. The client sends, for rule "AUTH-BRUTE-FORCE-001":
 *
 *   { threshold: 8, enabled: false, previouslyUpdatedAt: "2026-11-11T10:00:00.000Z" }
 *
 * and this function returns the parts marked below:
 *
 *   new UpdateCommand({
 *     TableName: "threatlens-detection-rules",
 *     Key: { ruleId: "AUTH-BRUTE-FORCE-001" },                    // built by the caller
 *
 *     UpdateExpression:                                          // <- returned
 *       "SET #updatedAt = :updatedAt, #threshold = :threshold, #enabled = :enabled",
 *     ExpressionAttributeNames: {                                // <- returned
 *       "#updatedAt": "updatedAt",
 *       "#threshold": "threshold",
 *       "#enabled": "enabled",
 *     },
 *     ExpressionAttributeValues: {                               // <- returned
 *       ":updatedAt": "2026-11-12T09:30:00.000Z",   // new concurrency token
 *       ":threshold": 8,
 *       ":enabled": false,
 *       ":previouslyUpdatedAt": "2026-11-11T10:00:00.000Z",
 *     },
 *     ConditionExpression: "#updatedAt = :previouslyUpdatedAt",   // <- returned
 *     ReturnValues: "ALL_NEW",                                   // built by the caller
 *   })
 *
 * In SQL terms: UPDATE ... SET <fields> WHERE ruleId = ? AND updatedAt = <expected>.
 *   - "#field" is a name placeholder (safe even for DynamoDB reserved words).
 *   - ":field" is a value placeholder (values never get concatenated into the string).
 *   - The condition is optimistic locking: the write fails with
 *     ConditionalCheckFailedException if someone else changed the rule first.
 *
 * Field names are interpolated into the expression. That is safe only because
 * the update schema is `.strict()` (unknown keys never reach this function).
 *
 * @see https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
 */
export const buildRuleUpdateExpression = (
	ruleId: DetectionRuleId,
	changes: RuleChanges,
	previouslyUpdatedAt: string,
	now: number = Date.now(),
): UpdateExpressionParts => {
	// Step 1: list every attribute to be updated as { field, value }.
	// `updatedAt` field is always written since it must stay updated with latest time -> newUpdatedAt variable does that
	// the rest are whatever the client sent.
	const changedFields = Object.entries(changes)
		.filter(([, value]) => value !== undefined) // take out the undefined ones
		.map(([fieldName, value]) => ({ fieldName, value }))

	// update the time value for the "updatedAt" field
	const newUpdatedAt = new Date(
		Math.max(now, Date.parse(previouslyUpdatedAt) + 1),
	).toISOString()

	let fieldsToUpdate = [
		{ fieldName: "updatedAt", value: newUpdatedAt },
		...changedFields,
	]

	// only allow enable/disable toggle for CLOUD TAMPERING rule
	const CLOUD_TAMPERING_RULE =
		DETECTION_RULES["Cloud-Infrastructure"].CLOUDTRAIL_TAMPERING.ruleId
	if (ruleId === CLOUD_TAMPERING_RULE) {
		// A request without `enabled` would otherwise turn the rule off by accident
		if (changes.enabled === undefined) {
			throw new HttpError(
				HTTP_STATUS.BAD_REQUEST,
				"Only the enabled field can be changed for this rule",
			)
		}

		fieldsToUpdate = [
			{ fieldName: "updatedAt", value: newUpdatedAt },
			{ fieldName: "enabled", value: changes.enabled },
		]
	}

	// Step 2: derive the three DynamoDB pieces from that one list.
	const updateExpression = fieldsToUpdate.map(
		({ fieldName }) => `#${fieldName} = :${fieldName}`,
	)

	const fieldNames = Object.fromEntries(
		fieldsToUpdate.map(({ fieldName }) => [`#${fieldName}`, fieldName]),
	)

	const fieldValues = Object.fromEntries(
		fieldsToUpdate.map(({ fieldName, value }) => [`:${fieldName}`, value]),
	)

	return {
		UpdateExpression: `SET ${updateExpression.join(", ")}`,
		ExpressionAttributeNames: fieldNames,
		ExpressionAttributeValues: {
			...fieldValues,
			":previouslyUpdatedAt": previouslyUpdatedAt,
		},
		ConditionExpression: "#updatedAt = :previouslyUpdatedAt",
	}
}
