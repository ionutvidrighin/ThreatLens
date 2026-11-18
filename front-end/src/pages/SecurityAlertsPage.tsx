import { SecurityAlertsHeader } from "@/components/security-alerts/SecurityAlertsHeader"
import { tableColumns } from "@/components/security-alerts/tableColumns"
import { DataTable } from "@/components/ui/DataTable"
import { DETECTION_RULES } from "@/constants"
import { useGetSecurityAlerts } from "@/queries/securityAlertsQueries"

export const SecurityAlertsPage = () => {
	const { data: alerts, isPending } = useGetSecurityAlerts()

	const alertsCount = alerts?.length

	return (
		<>
			<SecurityAlertsHeader alertsCount={alertsCount} />
			{!isPending && (
				<DataTable
					caption="Security alerts"
					columns={tableColumns}
					data={alerts ?? []} // flattened pages from useInfiniteQuery
					getRowId={(alert) => alert.alertId}
					getRowClassName={(rule) =>
						rule.ruleId === DETECTION_RULES.CLOUDTRAIL_TAMPERING
							? "bg-red-400/85 **:text-black!"
							: undefined
					}
					emptyMessage="No alerts found."
					className="max-h-[65vh]" // rows scroll inside, header stays pinned
				/>
			)}
		</>
	)
}
