import type { DetectionRule } from "@/api/types"
import { DETECTION_RULES } from "@/constants"
import { Badge } from "../ui/Badge"
import { createColumn } from "../ui/DataTable"
import { CellHint, CellTitle } from "../ui/Table"

export const column = createColumn<DetectionRule>()

export const baseColumns = column.columns([
	column.accessor("ruleId", {
		header: "Rule",
		cell: (info) => {
			const { label, category, ruleId } = info.row.original

			return (
				<>
					<CellTitle>{label}</CellTitle>
					<p>{category}</p>
					<CellHint>{ruleId}</CellHint>
				</>
			)
		},
	}),
	column.accessor("enabled", {
		header: "Status",
		cell: (info) => (
			<Badge tone={info.getValue() ? "enabled" : "disabled"}>
				{info.getValue() ? "Enabled" : "Disabled"}
			</Badge>
		),
	}),
	column.accessor("threshold", {
		header: "Threshold",
		cell: (info) => {
			const ruleId = info.row.original.ruleId
			const isPasswordSpraying = ruleId === DETECTION_RULES.PASSWORD_SPRAYING
			const isCloudTrailTampering =
				ruleId === DETECTION_RULES.CLOUDTRAIL_TAMPERING

			return (
				<>
					{info.getValue() ?? "-"}
					{!isCloudTrailTampering && (
						<CellHint>
							{isPasswordSpraying ? "distinct accounts" : "failed attempts"}
						</CellHint>
					)}
				</>
			)
		},
	}),
	column.accessor("windowSeconds", {
		header: "Window",
		cell: (info) => {
			const seconds = info.getValue()

			if (seconds) {
				return seconds >= 60 && seconds % 60 === 0
					? `${seconds / 60} min`
					: `${seconds} sec`
			}
			return "-"
		},
	}),
	column.accessor("severity", {
		header: "Severity",
		cell: (info) => <Badge tone={info.getValue()}>{info.getValue()}</Badge>,
	}),
	column.accessor("updatedAt", {
		header: "Last updated",
		cell: (info) => (
			<time dateTime={info.getValue()}>
				{new Date(info.getValue()).toLocaleString("RO-ro")}
			</time>
		),
	}),
])
