import { z } from "zod"
import { DetectionRuleSchema } from "./detectionRule.schema"

export const DetectionRuleUpdateSchema = DetectionRuleSchema.pick({
	enabled: true,
	threshold: true,
	windowSeconds: true,
	severity: true,
})
	.partial()
	.extend({
		previouslyUpdatedAt: z.iso.datetime(),
	})
	.strict()
	.refine(
		(update) =>
			update.enabled !== undefined ||
			update.threshold !== undefined ||
			update.windowSeconds !== undefined ||
			update.severity !== undefined,
		{ message: "At least one editable field must be provided" },
	)

export type DetectionRuleUpdateType = z.infer<typeof DetectionRuleUpdateSchema>
