import { z } from "zod"

export const detectionRuleSchema = z.object({
	ruleId: z.string().min(1),
	enabled: z.boolean(),
	category: z.string().min(1),
	label: z.string().min(1),
	threshold: z.number().int().min(1).optional(),
	windowSeconds: z.number().int().min(1).max(86400).optional(),
	severity: z.enum(["low", "medium", "high", "critical"]),
	updatedAt: z.iso.datetime(),
})

export const fetchedRulesSchema = z.array(detectionRuleSchema)

export const updateDetectionRuleSchema = detectionRuleSchema
	.pick({
		enabled: true,
		threshold: true,
		windowSeconds: true,
		severity: true,
	})
	.partial()
	.extend({ previouslyUpdatedAt: z.iso.datetime() })
	.strict()
	.refine(
		(update) =>
			Object.entries(update).some(
				([field, value]) =>
					field !== "expectedUpdatedAt" && value !== undefined,
			),
		{ message: "Change at least one field before saving." },
	)
