import { z } from "zod"

export const DetectionRuleSchema = z.object({
	ruleId: z.string().min(1),
	enabled: z.boolean(),
	category: z.string().min(1),
	label: z.string().min(1),
	threshold: z.number().int().min(1).optional(),
	windowSeconds: z.number().int().min(1).max(86400).optional(),
	severity: z.enum(["low", "medium", "high", "critical"]),
	updatedAt: z.iso.datetime(),
})
