import { ActivityChart } from "@/components/overview/ActivityChart"
import { OverviewMetrics } from "@/components/overview/OverviewMetrics"
import { RecentAlerts } from "@/components/overview/RecentAlerts"
import { RuleStatusChart } from "@/components/overview/RuleStatusChart"
import { Button } from "@/components/ui/Button"
import { PageHeading } from "@/components/ui/Typography"
import { toast } from "@/notifications"
import { useGetRules } from "@/queries/detectionRulesQueries"
import { useGetSecurityAlerts } from "@/queries/securityAlertsQueries"

export const OverviewPage = () => {
	const {
		data: rulesList,
		isPending,
		isLoading,
		isFetching,
		isError,
		refetch,
	} = useGetRules()

	useGetSecurityAlerts()

	const refreshRulesList = async () => {
		const { isSuccess } = await refetch()
		if (isSuccess) {
			toast.success("Rule metrics refreshed", { id: "overview-refresh" })
		}
	}

	return (
		<>
			<PageHeading
				eyebrow="SECURITY OPERATIONS"
				title="Overview"
				subtitle="Your security posture, at a glance."
			>
				<Button disabled={isFetching} onClick={() => refreshRulesList()}>
					{isFetching ? "Refreshing..." : "Refresh rules"}
				</Button>
			</PageHeading>
			<OverviewMetrics
				rules={rulesList}
				isPending={isPending}
				isError={isError}
			/>
			<div className="mb-6.5 grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)] gap-5.5 max-[1100px]:grid-cols-1 max-[760px]:gap-4.5">
				<ActivityChart />
				<RuleStatusChart rules={rulesList} isLoading={isLoading} />
			</div>
			<RecentAlerts />
		</>
	)
}
