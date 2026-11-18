import type { DetectionRule } from "@/api/types"
import { Panel, PanelHeading, PanelLabel } from "@/components/ui/Panel"
import { ChartLegend, LegendItem, LegendValue } from "./ChartLegend"

export function RuleStatusChart({
	rules,
	isLoading,
}: {
	rules: DetectionRule[] | undefined
	isLoading: boolean
}) {
	const total = rules?.length ?? 0
	const enabled = rules?.filter((rule) => rule.enabled).length ?? 0
	const percent = total ? (enabled / total) * 100 : 0
	return (
		<Panel aria-labelledby="rule-status-title">
			<PanelHeading
				dense
				titleId="rule-status-title"
				title="Rule status"
				description="Enabled and disabled detection rules"
			>
				<PanelLabel>Live rules</PanelLabel>
			</PanelHeading>
			<div className="grid h-[230px] place-items-center p-6">
				<div
					className="grid size-[175px] place-items-center rounded-full"
					role="img"
					aria-label={
						rules
							? `${enabled} enabled and ${total - enabled} disabled rules`
							: "Rule status not available"
					}
					style={{
						background: total
							? `conic-gradient(var(--color-accent-teal) 0% ${percent}%, var(--color-line-strong) ${percent}% 100%)`
							: "var(--color-line)",
					}}
				>
					<div className="flex size-[135px] flex-col items-center justify-center rounded-full bg-surface">
						<strong className="font-display text-[32px] font-extrabold text-heading">
							{rules ? total : "-"}
						</strong>
						<span className="mt-[5px] text-[10px] text-faint">
							Total rules
						</span>
					</div>
				</div>
			</div>
			<ChartLegend>
				<LegendItem color="bg-accent-teal">
					Enabled <LegendValue>{rules ? enabled : "-"}</LegendValue>
				</LegendItem>
				<LegendItem color="bg-line-strong">
					Disabled <LegendValue>{rules ? total - enabled : "-"}</LegendValue>
				</LegendItem>
			</ChartLegend>
			{!rules && (
				<p
					className="pb-[15px] text-center text-[10px] text-faint"
					role="status"
				>
					{isLoading
						? "Loading rule configuration..."
						: "Rule configuration is unavailable."}
				</p>
			)}
		</Panel>
	)
}
