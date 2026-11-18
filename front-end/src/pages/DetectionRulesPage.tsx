import { DetectionRulesDashboard } from "@/components/detection-rules/DetectionRulesDashboard"
import { PageHeading } from "@/components/ui/Typography"
import { useSession } from "@/hooks/useSession"

export function DetectionRulesPage() {
	const { canEditRules: canEdit } = useSession()

	return (
		<>
			<PageHeading
				eyebrow="SECURITY OPERATIONS"
				title="Detection rules"
				subtitle="Understand the rules watching your authentication events."
			>
				<span className="whitespace-nowrap rounded-md border border-line-strong bg-surface px-3 py-2 text-[11px]">
					{canEdit ? "Rule administration" : "Read-only dashboard"}
				</span>
			</PageHeading>
			<DetectionRulesDashboard canEdit={canEdit} />
		</>
	)
}
