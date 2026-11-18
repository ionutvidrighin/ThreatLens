import { useState } from "react"
import type { DetectionRule } from "@/api/types"
import { toast } from "@/notifications"
import { useGetRules } from "@/queries/detectionRulesQueries"
import { EditRuleDialog } from "../EditRuleDialog"
import { Button } from "../ui/Button"
import {
	emptyStateClass,
	footnoteClass,
	Panel,
	PanelHeading,
} from "../ui/Panel"
import { DetectionRuleSummary } from "./DetectionRuleSummary"
import { DetectionRulesTable } from "./DetectionRulesTable"

export const DetectionRulesDashboard = ({ canEdit }: { canEdit: boolean }) => {
	const [editingRule, setEditingRule] = useState<DetectionRule | null>(null)
	const [editorRevision, setEditorRevision] = useState(0)

	const {
		data: rulesList,
		isPending,
		isLoading,
		isFetching,
		isError,
		refetch: refetchRulesList,
	} = useGetRules()

	const handleRefreshRules = async () => {
		const { isSuccess } = await refetchRulesList()
		if (isSuccess)
			toast.success("Rule configurations refreshed", { id: "rules-refreshed" })
	}

	const reloadEditingRule = async () => {
		if (!editingRule) {
			return
		}

		const result = await refetchRulesList()
		if (!result.isSuccess) {
			return
		}

		const latest = result.data.find(
			(rule) => rule.ruleId === editingRule.ruleId,
		)
		if (!latest) {
			setEditingRule(null)
			toast.error("This rule no longer exists.")
			return
		}
		setEditingRule({ ...latest })
		setEditorRevision((value) => value + 1)
		toast.info("Latest rule loaded. Review the values before saving.")
	}

	return (
		<>
			<DetectionRuleSummary rules={rulesList} />
			<Panel aria-labelledby="rule-configurations-title" aria-busy={isFetching}>
				<PanelHeading
					titleId="rule-configurations-title"
					title="Rule configurations"
					description="Current settings from your detection engine."
				>
					<Button disabled={isFetching} onClick={() => handleRefreshRules()}>
						{isLoading
							? "Loading..."
							: isFetching
								? "Refreshing..."
								: "Refresh rules"}
					</Button>
				</PanelHeading>
				{isPending ? (
					<p className={emptyStateClass} role="status">
						{isLoading
							? "Loading detection rules..."
							: "Waiting for a connection to load detection rules..."}
					</p>
				) : !rulesList ? (
					<p className={emptyStateClass}>
						Rules could not be loaded. Select Refresh rules to try again.
					</p>
				) : (
					<>
						{isError && (
							<p className={footnoteClass} role="status">
								Refresh failed. Showing previously loaded rules.
							</p>
						)}
						{rulesList.length === 0 ? (
							<p className={emptyStateClass}>
								No detection rules were returned.
							</p>
						) : (
							<DetectionRulesTable
								detectionRules={rulesList}
								canEdit={canEdit}
								onEdit={setEditingRule}
							/>
						)}
					</>
				)}
			</Panel>
			<p className={footnoteClass}>
				Detection engine configuration changes can take up to 60 seconds to take
				effect.
			</p>
			{canEdit && editingRule && (
				<EditRuleDialog
					key={`${editingRule.ruleId}:${editingRule.updatedAt}:${editorRevision}`}
					ruleItem={editingRule}
					onClose={() => setEditingRule(null)}
					onReload={reloadEditingRule}
				/>
			)}
		</>
	)
}
