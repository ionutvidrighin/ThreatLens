import {
	KeyRound,
	LayoutDashboard,
	Network,
	ShieldExclamationPoint,
	SlidersHorizontal,
} from "lucide-react"

export const ROUTES = {
	HOME: "/",
	OVERVIEW: "/overview",
	DETECTION_RULES: "/detection-rules",
	SECURITY_ALERTS: "/security-alerts",
	CALLBACK: "/callback",
} as const

/** Sidebar navigation, grouped under a small section label. */
export const sidemenuSections = [
	{
		label: "SECURITY OPERATIONS",
		items: [
			{ label: "Overview", to: ROUTES.OVERVIEW, icon: LayoutDashboard },
			{
				label: "Security Alerts",
				to: ROUTES.SECURITY_ALERTS,
				icon: ShieldExclamationPoint,
			},
			{ label: "Events", to: "/events", icon: KeyRound },
			{ label: "Network Events", to: "/alertsss", icon: Network },
		],
	},
	{
		label: "CONFIGURATION",
		items: [
			{
				label: "Detection Rules",
				to: ROUTES.DETECTION_RULES,
				icon: SlidersHorizontal,
			},
		],
	},
] as const
