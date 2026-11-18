import type { HTMLAttributes } from "react"
import { cn } from "@/lib/cn"

export const Eyebrow = ({
	className,
	...props
}: HTMLAttributes<HTMLParagraphElement>) => {
	return (
		<p
			className={cn(
				"mb-3 text-[10px] font-bold tracking-[2px] text-accent-teal",
				className,
			)}
			{...props}
		/>
	)
}

export const H1 = ({
	className,
	...props
}: HTMLAttributes<HTMLHeadingElement>) => {
	return (
		<h1
			className={cn(
				"mb-3 font-display text-[38px] font-extrabold tracking-[-1.5px] text-heading max-[700px]:text-[30px]",
				className,
			)}
			{...props}
		/>
	)
}

export const PageHeading = ({
	eyebrow,
	title,
	subtitle,
	children,
}: {
	eyebrow: string
	title: string
	subtitle: string
	children?: React.ReactNode
}) => {
	return (
		<div className="mb-9 flex items-center justify-between gap-5 max-[700px]:flex-col max-[700px]:items-start">
			<div>
				<Eyebrow>{eyebrow}</Eyebrow>
				<H1>{title}</H1>
				<p className="m-0 text-sm text-muted">{subtitle}</p>
			</div>
			{children}
		</div>
	)
}
