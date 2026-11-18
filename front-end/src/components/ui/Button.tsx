import type { ButtonHTMLAttributes } from "react"
import { cn } from "@/lib/cn"

const variants = {
	primary: "border-brand bg-brand text-white hover:bg-brand-dark",
	secondary:
		"border-line-strong bg-surface-2 text-ink hover:bg-hover hover:text-heading",
	/** For dark surfaces such as the top bar. */
	ghost: "border-line-strong bg-transparent text-ink hover:bg-white/10",
}

export type ButtonVariant = keyof typeof variants

/** Also usable on `<Link>` so links can look like buttons. */
export const buttonClass = (variant: ButtonVariant, className?: string) =>
	cn(
		"inline-flex items-center justify-center gap-[18px] rounded-md border px-4 py-[11px] text-xs font-semibold disabled:cursor-wait disabled:opacity-65",
		variants[variant],
		className,
	)

export const Button = ({
	variant = "secondary",
	type = "button",
	className,
	...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) => {
	return (
		<button
			type={type}
			className={buttonClass(variant, className)}
			{...props}
		/>
	)
}
