import { useMemo } from "react"
import type { DetectionRule } from "@/api/types"
import { DETECTION_RULES } from "@/constants"
import { Button } from "../ui/Button"
import { DataTable } from "../ui/DataTable"
import { baseColumns, column } from "./tableColumns"

type DetectionRulesTableProps = {
	detectionRules: DetectionRule[]
	canEdit: boolean
	onEdit: (rule: DetectionRule) => void
}

export const DetectionRulesTable = ({
	detectionRules,
	canEdit,
	onEdit,
}: DetectionRulesTableProps) => {
	// The Actions column depends on props, so build the array once per change
	// (the table needs a stable `columns` reference between renders).
	const columns = useMemo(() => {
		if (!canEdit) {
			return baseColumns
		}

		return [
			...baseColumns,
			column.display({
				id: "actions",
				header: "Actions",
				cell: (info) => (
					<Button
						onClick={() => onEdit({ ...info.row.original })}
						aria-label={`Edit ${info.row.original.ruleId}`}
					>
						Edit
					</Button>
				),
			}),
		]
	}, [canEdit, onEdit])

	return (
		<DataTable
			caption="Authentication detection rule configurations"
			columns={columns}
			data={detectionRules}
			getRowId={(rule) => rule.ruleId}
			emptyMessage="No detection rules found."
		/>
	)
}
