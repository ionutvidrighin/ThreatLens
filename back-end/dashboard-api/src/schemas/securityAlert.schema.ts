import { z } from "zod"
import type { SECURITY_ALERTS_FILTERS } from "@/repositories/utils/securityAlertsHelpers"

/**
 * Shape of an alert as stored in `threatlens-security-alerts` by the
 * detection engine (see detection-engine/src/types.ts `SecurityAlert`).
 *
 * This validates data READ from DynamoDB, so it mirrors what is stored and
 * stays lenient where the writer is: one unexpected record must not make the
 * whole list endpoint fail.
 */
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
export type SecurityAlertType = z.infer<typeof SecurityAlertSchema>

export type FilterType = keyof typeof SECURITY_ALERTS_FILTERS

/**
 * Pagination for the various filters
 *   -> see SECURITY_ALERTS_FILTERS in /repositories/utils/securityAlertsHelpers.ts
 * contains:
 *  -> alertId - (table primary key)
 *  -> entityType / ruleId / sourceIp / severity
 * - > createdAt
 * this lets Dynamo know where it stopped and from where should it continue when querying more data
 */
export const EntityTypeFilterSchema = z.object({
	alertId: z.string().min(1),
	entityType: z.string().min(1),
	createdAt: z.iso.datetime(),
})
export type EntityTypeFilterSchemaType = z.infer<typeof EntityTypeFilterSchema>

export const RuleIdFilterSchema = z.object({
	alertId: z.string().min(1),
	ruleId: z.string().min(1),
	createdAt: z.iso.datetime(),
})
export type RuleIdFilterType = z.infer<typeof RuleIdFilterSchema>

export const SourceIpFilterSchema = z.object({
	alertId: z.string().min(1),
	sourceIp: z.string().min(1),
	createdAt: z.iso.datetime(),
})
export type SourceIpFilterType = z.infer<typeof SourceIpFilterSchema>

export const SeverityFilterSchema = z.object({
	alertId: z.string().min(1),
	severity: z.string().min(1),
	createdAt: z.iso.datetime(),
})
export type SeverityFilterType = z.infer<typeof SeverityFilterSchema>

export const AlertsFiltersQuerySchema = z
	.object({
		limit: z.coerce.number().int().min(1).max(100).default(20),
		cursor: z.string().optional(),
		entityType: z.string().optional(),
		ruleId: z.string().optional(),
		sourceIp: z.string().optional(),
		severity: z.enum(["low", "medium", "high", "critical"]).optional(),
	})
	.strict()

// pagination key of whichever filter (index) was used
export type AlertPageKeyType =
	| EntityTypeFilterSchemaType
	| RuleIdFilterType
	| SourceIpFilterType
	| SeverityFilterType

export type GetSecurityAlertsParams = {
	filterType: FilterType
	filterValue: string
	limit: number
	exclusiveStartKey?: AlertPageKeyType
}

export type SecurityAlertsResponse = {
	alerts: SecurityAlertType[]
	lastEvaluatedKey?: AlertPageKeyType // this only exists where requesting more pages of data
}
