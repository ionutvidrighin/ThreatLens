import type { ReactNode, TdHTMLAttributes } from "react"
import { cn } from "@/lib/cn"

/**
 * The wrapper is the scroll container. Give it a height limit through
 * `className` (e.g. `max-h-[65vh]`) to make the table scroll inside itself
 * with the header row pinned to the top. Without a height limit it only
 * scrolls horizontally, and the page scrolls as usual.
 */
export const Table = ({
	caption,
	className,
	children,
}: {
	caption: string
	className?: string
	children: ReactNode
}) => {
	return (
		<div className={cn("overflow-auto", className)}>
			<table className="w-full whitespace-nowrap border-collapse text-left">
				<caption className="sr-only">{caption}</caption>
				{children}
			</table>
		</div>
	)
}

// `sticky` pins the header cells to the top of the scrolling wrapper. The cell
// background must be opaque so rows do not show through. The bottom line is an
// inset shadow because `border-collapse` borders do not move with sticky cells.
export const Th = ({ children }: { children: ReactNode }) => {
	return (
		<th className="sticky top-0 z-10 bg-surface-2 px-5 py-4 text-left text-[10px] font-semibold uppercase tracking-[0.8px] text-muted shadow-[inset_0_-1px_0_var(--color-line-soft)]">
			{children}
		</th>
	)
}

export const Td = ({
	className,
	...props
}: TdHTMLAttributes<HTMLTableCellElement>) => {
	return (
		<td
			className={cn(
				"border-t border-line-soft px-5 py-6 text-xs text-ink-soft first:pl-6.5",
				className,
			)}
			{...props}
		/>
	)
}

/** Primary text in a table cell. */
export const CellTitle = ({ children }: { children: ReactNode }) => {
	return (
		<strong className="text-[13px] font-semibold text-heading">
			{children}
		</strong>
	)
}

/** Secondary line under a cell value. */
export const CellHint = ({ children }: { children: ReactNode }) => {
	return (
		<small className="mt-1.75 block text-[10px] text-faint">{children}</small>
	)
}
