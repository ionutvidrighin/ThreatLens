import type { z } from "zod"
import type {
	detectionRuleSchema,
	updateDetectionRuleSchema,
} from "./schemas/detectionRules.schemas"
import type { SecurityAlertSchema } from "./schemas/securityAlerts.schemas"

export type DetectionRule = z.infer<typeof detectionRuleSchema>

export type UpdateDetectionRule = z.infer<typeof updateDetectionRuleSchema>

export type SecurityAlert = z.infer<typeof SecurityAlertSchema>
