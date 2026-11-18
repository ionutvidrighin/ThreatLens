import { Panel, PanelHeading, PanelLabel } from "@/components/ui/Panel"
import { Table, Td, Th } from "@/components/ui/Table"

export function RecentAlerts() {
	return (
		<Panel aria-labelledby="recent-alerts-title">
			<PanelHeading
				titleId="recent-alerts-title"
				title="Recent alerts"
				description="The latest findings from your detection engine"
			>
				<PanelLabel>Awaiting alert data</PanelLabel>
			</PanelHeading>
			<Table caption="Recent security alerts">
				<thead>
					<tr>
						<Th>Alert</Th>
						<Th>Severity</Th>
						<Th>Source IP</Th>
						<Th>Status</Th>
						<Th>Detected</Th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<Td colSpan={5}>
							<div className="px-4 py-[30px] text-center max-[760px]:px-0 max-[760px]:py-6">
								<strong className="text-[13px] font-semibold">
									Recent alerts will appear here
								</strong>
								<p className="mx-auto mt-3 max-w-[540px] whitespace-normal text-[11px] leading-[1.8] text-faint">
									Alert history is not connected yet. This does not indicate
									that there are no open alerts.
								</p>
							</div>
						</Td>
					</tr>
				</tbody>
			</Table>
		</Panel>
	)
}
