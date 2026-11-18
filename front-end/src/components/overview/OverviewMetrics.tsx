import type { DetectionRule } from "@/api/types"

const markerColors = {
	amber: "bg-accent-orange",
	blue: "bg-accent-blue",
	green: "bg-accent-green",
	purple: "bg-accent-violet",
}

export function OverviewMetrics({
	rules,
	isPending,
	isError,
}: {
	rules: DetectionRule[] | undefined
	isPending: boolean
	isError: boolean
}) {
	const enabled = rules?.filter((rule) => rule.enabled).length
	const metrics = [
		{
			label: "Open alerts",
			value: "-",
			detail: "Alert data not available yet",
			accent: "amber",
		},
		{
			label: "Events today",
			value: "-",
			detail: "Event data not available yet",
			accent: "blue",
		},
		{
			label: "Enabled rules",
			value: enabled ?? "-",
			detail: rules
				? `${enabled} of ${rules.length} rules enabled`
				: isPending
					? "Loading rules..."
					: isError
						? "Rule data unavailable"
						: "Waiting for rule data",
			accent: "green",
		},
		{
			label: "Detection rate",
			value: "-",
			detail: "Awaiting detection metrics",
			accent: "purple",
		},
	] as const
	return (
		<section
			className="mb-[26px] grid grid-cols-4 gap-[18px] max-[1100px]:grid-cols-2 max-[760px]:gap-3"
			aria-label="Security overview metrics"
		>
			{metrics.map((metric) => (
				<article
					key={metric.label}
					className="rounded-[10px] border border-line bg-surface p-6 max-[760px]:p-[18px]"
				>
					<div className="flex items-center justify-between gap-3 text-xs text-muted max-[760px]:text-[11px]">
						<span>{metric.label}</span>
						<span
							className={`size-[9px] rounded-[3px] ${markerColors[metric.accent]}`}
							aria-hidden="true"
						/>
					</div>
					<strong className="mt-[18px] mb-2.5 block font-display text-[34px] font-extrabold text-heading max-[760px]:text-[28px]">
						{metric.value}
					</strong>
					<p className="m-0 text-[10px] leading-[1.6] text-faint">
						{metric.detail}
					</p>
				</article>
			))}
		</section>
	)
}
