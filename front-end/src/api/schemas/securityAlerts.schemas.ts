import z from "zod"

export const SecurityAlertSchema = z.object({
	alertId: z.string().min(1),
	entityType: z.literal("ALERT"),
	ruleId: z.string().min(1),
	ruleName: z.string().min(1),
	severity: z.enum(["low", "medium", "high", "critical"]),
	status: z.enum(["open"]),
	sourceIp: z.string().min(1),
	windowStart: z.iso.datetime(),
	windowEnd: z.iso.datetime(),
	createdAt: z.iso.datetime(),
	description: z.string().min(1),
	failedAttempts: z.number().int().nonnegative().optional(),
	targetedAccounts: z.number().int().nonnegative().optional(),
	usernames: z.array(z.string()).optional(),
})

export const fetchedSecurityAlertsSchema = z.object({
	alertsList: z.array(SecurityAlertSchema),
})
