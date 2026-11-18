import type { ReactNode } from "react"

export const ChartLegend = ({ children }: { children: ReactNode }) => {
	return (
		<div className="flex flex-wrap justify-center gap-6 px-[15px] pt-3 pb-6 text-[10px] text-muted">
			{children}
		</div>
	)
}

export const LegendItem = ({
	color,
	children,
}: {
	/** Tailwind background class for the dot, e.g. `bg-accent-blue`. */
	color: string
	children: ReactNode
}) => {
	return (
		<span className="flex items-center gap-[7px]">
			<i className={`inline-block size-[7px] rounded-full ${color}`} />
			{children}
		</span>
	)
}

/** Emphasised value inside a legend item. */
export const LegendValue = ({ children }: { children: ReactNode }) => {
	return <b className="font-semibold text-ink">{children}</b>
}
