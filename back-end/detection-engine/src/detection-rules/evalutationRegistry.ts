import type { DetectionRuleWithEvalution } from "../types"
import { DETECTION_RULES } from "./detectionRules"
import { evaluateForBruteForceAttack } from "./evaluationAttacks/bruteForceAttack"
import { evaluateForCloudTrailTampering } from "./evaluationAttacks/cloudTrailTamperingAttack"
import { evaluateForPasswordSprayingAttack } from "./evaluationAttacks/passwordSprayingAttack"
import { evaluateForSuccessLoginAfterFailure } from "./evaluationAttacks/successLoginAfterFailure"

export const detectionRuleEvaluationRegistry: readonly DetectionRuleWithEvalution[] =
	[
		{
			id: DETECTION_RULES.Authentication.BRUTE_FORCE.ruleId,
			eventType: "authentication",
			evaluate: ({ event, recentFailures, configuration }) =>
				evaluateForBruteForceAttack(event, recentFailures, configuration),
		},
		{
			id: DETECTION_RULES.Authentication.PASSWORD_SPRAYING.ruleId,
			eventType: "authentication",
			evaluate: ({ event, recentFailures, configuration }) =>
				evaluateForPasswordSprayingAttack(event, recentFailures, configuration),
		},
		{
			id: DETECTION_RULES.Authentication.SUCCESS_LOGIN_AFTER_FAILURES.ruleId,
			eventType: "authentication",
			evaluate: ({ event, recentFailures, configuration }) =>
				evaluateForSuccessLoginAfterFailure(
					event,
					recentFailures,
					configuration,
				),
		},
		{
			id: DETECTION_RULES["Cloud-Infrastructure"].CLOUDTRAIL_TAMPERING.ruleId,
			eventType: "cloudtrail",
			evaluate: ({ event, configuration }) =>
				evaluateForCloudTrailTampering(event, configuration),
		},
	]
