import { DETECTION_RULES } from "@/repositories/utils/detectionRulesHelpers"

export const BRUTE_FORCE_RULE_ID =
	DETECTION_RULES.Authentication.BRUTE_FORCE.ruleId
export const PASSWORD_SPRAYING_RULE_ID =
	DETECTION_RULES.Authentication.PASSWORD_SPRAYING.ruleId
export const CLOUDTRAIL_TAMPERING_RULE_ID =
	DETECTION_RULES["Cloud-Infrastructure"].CLOUDTRAIL_TAMPERING.ruleId

/** A rule configuration row exactly as stored in the detection rules table. */
export const ruleConfig = (
	ruleId: string,
	overrides: Record<string, unknown> = {},
) => ({
	ruleId,
	enabled: true,
	category: "Authentication",
	label: "Test rule",
	threshold: 5,
	windowSeconds: 300,
	severity: "high",
	updatedAt: "2026-01-01T00:00:00.000Z",
	...overrides,
})
