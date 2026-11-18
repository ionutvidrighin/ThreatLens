import { PageHeading } from "@/components/ui/Typography"

export const SecurityAlertsHeader = ({
	alertsCount,
}: {
	alertsCount?: number
}) => {
	return (
		<PageHeading
			eyebrow="SECURITY OPERATIONS"
			title="Security alerts"
			subtitle="Review the alerts raised by your detection rules."
		>
			<div className="flex flex-col items-end gap-2 self-end max-[700px]:items-start max-[700px]:self-start">
				<div className="whitespace-nowrap rounded-md border border-line-strong bg-surface px-3 py-2 text-[11px]">
					Newest first
				</div>
				<p className="m-0 text-sm text-muted">
					Alerts count: {alertsCount ?? "-"}
				</p>
			</div>
		</PageHeading>
	)
}
