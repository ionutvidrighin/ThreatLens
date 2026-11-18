import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb"
import { detectionRuleEvaluationRegistry } from "../detection-rules/evalutationRegistry"
import { validateDetectionRuleConfig } from "../detection-rules/helpers"
import { DetectionRuleSchema } from "../schemas/detectionRuleConfig.schema"
import type { DetectionRule } from "../types"

const CACHE_TTL_MS = 60_000

const dynamodb = DynamoDBDocumentClient.from(new DynamoDBClient({}))

// Every rule config in the table (enabled or not). Lives for the lifetime of
// the warm Lambda container.
let cache: { detectionRule: DetectionRule[]; expiresAt: number } | null = null

const loadRuleConfigurations = async (): Promise<DetectionRule[]> => {
	if (cache !== null && Date.now() < cache.expiresAt) {
		return cache.detectionRule
	}

	const TABLE_NAME = process.env.DETECTION_RULES_TABLE_NAME

	if (!TABLE_NAME) {
		throw new Error("DETECTION_RULES_TABLE_NAME env var is missing")
	}

	const response = await dynamodb.send(
		new ScanCommand({ TableName: TABLE_NAME, ConsistentRead: true }),
	)

	const detectionRulesList = (response.Items ?? []).map((item) =>
		DetectionRuleSchema.parse(item),
	)

	cache = {
		detectionRule: detectionRulesList,
		expiresAt: Date.now() + CACHE_TTL_MS,
	}

	return detectionRulesList
}

/**
 * Registered rules paired with their stored configuration, enabled ones only.
 * A registered rule with no configuration row, or an enabled one whose row is not
 * usable by that rule (e.g. no threshold), is an error; a disabled one is skipped.
 */
export const fetchDetectionRules = async () => {
	const detectionRulesById = new Map(
		(await loadRuleConfigurations()).map((rule) => [rule.ruleId, rule]),
	)

	return detectionRuleEvaluationRegistry.flatMap((detectionRule) => {
		const ruleConfiguration = detectionRulesById.get(detectionRule.id)

		if (!ruleConfiguration) {
			throw new Error(
				`Missing configuration for detection rule: ${detectionRule.id}`,
			)
		}

		if (!ruleConfiguration.enabled) {
			return []
		}

		if (!validateDetectionRuleConfig(ruleConfiguration, detectionRule.id)) {
			throw new Error(
				`Invalid configuration for detection rule: ${detectionRule.id}`,
			)
		}

		return [{ detectionRule, configuration: ruleConfiguration }]
	})
}

/** Test helper: drop the cached configurations. */
export const clearDetectionRulesCache = () => {
	cache = null
}
