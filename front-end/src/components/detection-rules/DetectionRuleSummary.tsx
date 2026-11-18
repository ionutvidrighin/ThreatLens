import type { ReactNode } from "react"
import type { DetectionRule } from "@/api/types"
import { cn } from "@/lib/cn"

function Stat({
	label,
	className,
	children,
}: {
	label: string
	className?: string
	children: ReactNode
}) {
	return (
		<div
			className={cn(
				"flex flex-col gap-3.5 rounded-[10px] border border-line bg-surface px-6.5 py-5.75",
				className,
			)}
		>
			<span className="text-xs text-muted">{label}</span>
			{children}
		</div>
	)
}

export function DetectionRuleSummary({
	rules,
}: {
	rules: DetectionRule[] | undefined
}) {
	return (
		<section
			className="mb-7 grid grid-cols-[1fr_1fr_1.5fr] gap-4.5 max-[700px]:grid-cols-2"
			aria-label="Rule overview"
		>
			<Stat label="Total rules">
				<strong className="font-display text-[30px] text-heading">
					{rules?.length ?? "-"}
				</strong>
			</Stat>
			<Stat label="Enabled">
				<strong className="font-display text-[30px] text-heading">
					{rules ? rules.filter((rule) => rule.enabled).length : "-"}
				</strong>
			</Stat>
			{/* <Stat label="Detection category" className="max-[700px]:col-span-full">
				<strong className="font-display text-[21px] leading-[41px] text-heading">
					Authentication
				</strong>
			</Stat> */}
		</section>
	)
}
