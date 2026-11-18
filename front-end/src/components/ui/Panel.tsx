import type { HTMLAttributes, ReactNode } from "react"
import { cn } from "@/lib/cn"

export const Panel = ({ className, ...props }: HTMLAttributes<HTMLElement>) => {
	return (
		<section
			className={cn(
				"overflow-hidden rounded-xl border border-line bg-surface",
				className,
			)}
			{...props}
		/>
	)
}

/** Centered placeholder text for empty, loading or error states. */
export const emptyStateClass =
	"px-[26px] py-[50px] text-center text-sm text-muted"

/** Small explanatory text below or inside a panel. */
export const footnoteClass = "mt-5 text-[11px] text-faint"

export const PanelHeading = ({
	titleId,
	title,
	description,
	descriptionClassName,
	dense = false,
	children,
}: {
	titleId: string
	title: string
	description: string
	descriptionClassName?: string
	/** Slightly tighter padding, used by the overview charts. */
	dense?: boolean
	children?: ReactNode
}) => {
	return (
		<div
			className={cn(
				"flex items-center justify-between gap-5 border-b border-line-soft px-6.5 py-6.25 max-[700px]:items-start max-[700px]:p-5",
				dense && "p-5.75 max-[760px]:p-5",
			)}
		>
			<div>
				<h2
					id={titleId}
					className="mb-1.5 font-display text-base font-bold text-heading"
				>
					{title}
				</h2>
				<p
					className={cn(
						"m-0 text-xs text-muted max-[700px]:max-w-45 max-[700px]:leading-[1.6]",
						dense && "min-[1000px]:text-[11px]",
						descriptionClassName,
					)}
				>
					{description}
				</p>
			</div>
			{children}
		</div>
	)
}

/** Small caption shown on the right side of a panel heading. */
export const PanelLabel = ({ children }: { children: ReactNode }) => {
	return (
		<span className="whitespace-nowrap text-[9px] text-faint">
			{children}
		</span>
	)
}
