/**
 * Single source of truth for ThreatLens API paths (relative to the API base URL).
 * Static paths are strings; paths with params are builder functions.
 */
export const ENDPOINTS = {
	detectionRules: {
		fetchRulesList: "/api/detection-rules",
		updateDetectionRuleById: (ruleId: string) =>
			`/api/detection-rules/${encodeURIComponent(ruleId)}`,
	},
	securityAlerts: {
		fetchAlerts: "/api/security-alerts",
	},
} as const
