export const DETECTION_RULES = {
	Authentication: {
		BRUTE_FORCE: {
			ruleId: "AUTH-BRUTE-FORCE-001",
			ruleName: "Multiple Failed Authentication Attempts",
		},
		PASSWORD_SPRAYING: {
			ruleId: "AUTH-PASSWORD-SPRAYING-001",
			ruleName: "Password Spraying Detection",
		},
		SUCCESS_LOGIN_AFTER_FAILURES: {
			ruleId: "AUTH-SUCCESS-AFTER-FAILURES-001",
			ruleName: "Successful Login After Multiple Failures",
		},
	},

	"IAM-and-Authorization": {
		PRIVILEGE_ESCALATION: {
			ruleId: "IAM-PRIVILEGE-ESCALATION-001",
			ruleName: "Potential IAM Privilege Escalation",
		},
		ROOT_ACCOUNT_USAGE: {
			ruleId: "IAM-ROOT-USAGE-001",
			ruleName: "AWS Root Account Activity",
		},
	},

	"Data-Security": {
		S3_PUBLIC_EXPOSURE: {
			ruleId: "DATA-S3-PUBLIC-001",
			ruleName: "Potential S3 Public Exposure",
		},
	},

	"Cloud-Infrastructure": {
		CLOUDTRAIL_TAMPERING: {
			ruleId: "CLOUD-TRAIL-TAMPERING-001",
			ruleName: "CloudTrail Logging Tampering",
		},
		SECURITY_GROUP_EXPOSURE: {
			ruleId: "CLOUD-SG-EXPOSURE-001",
			ruleName: "Security Group Internet Exposure",
		},
	},
} as const

export const DETECTION_RULE_IDS = Object.values(DETECTION_RULES).flatMap(
	(category) => Object.values(category).map((rule) => rule.ruleId),
)

type DetectionCategories = typeof DETECTION_RULES

// Indexing per category (not through the union of categories) keeps each
// category's keys, so the result is the union of every rule ID literal.
type RuleObjects = {
	[Category in keyof DetectionCategories]: DetectionCategories[Category][keyof DetectionCategories[Category]]
}[keyof DetectionCategories]

export type DetectionRuleId = RuleObjects["ruleId"]

/** Type guard: narrows a raw string (e.g. a path parameter) to a known rule ID. */
export const isDetectionRuleId = (ruleId: string): ruleId is DetectionRuleId =>
	DETECTION_RULE_IDS.some((id) => id === ruleId)
