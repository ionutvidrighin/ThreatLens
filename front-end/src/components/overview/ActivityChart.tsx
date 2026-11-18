import { Panel, PanelHeading, PanelLabel } from "@/components/ui/Panel"
import { ChartLegend, LegendItem } from "./ChartLegend"

export function ActivityChart() {
	return (
		<Panel aria-labelledby="activity-title">
			<PanelHeading
				dense
				titleId="activity-title"
				title="Event activity"
				description="Authentication and network events over time"
			>
				<PanelLabel>Line chart</PanelLabel>
			</PanelHeading>
			<div className="relative h-[230px] px-[22px] pt-[15px]">
				<svg
					className="h-full w-full"
					viewBox="0 0 600 210"
					aria-hidden="true"
					preserveAspectRatio="none"
				>
					{[30, 75, 120, 165].map((y) => (
						<line
							key={y}
							x1="30"
							y1={y}
							x2="580"
							y2={y}
							stroke="#2c3448"
							strokeDasharray="4 5"
						/>
					))}
					<path d="M30 15V185H580" fill="none" stroke="#38425b" />
				</svg>
				<div className="absolute inset-0 flex flex-col items-center justify-center p-5 text-center">
					<strong className="rounded-sm bg-surface-2 px-3 py-2 text-xs text-ink-soft">
						Activity trends will appear here
					</strong>
					<p className="text-[10px] text-faint">
						Event history is not connected yet.
					</p>
				</div>
			</div>
			<ChartLegend>
				<LegendItem color="bg-accent-blue">Authentication events</LegendItem>
				<LegendItem color="bg-accent-violet">Network events</LegendItem>
			</ChartLegend>
		</Panel>
	)
}
