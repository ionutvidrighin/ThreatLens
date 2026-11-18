import type { ReactNode } from "react"
import { cn } from "@/lib/cn"

const tones = {
	enabled: "bg-[#16352a] text-[#6fcf97]",
	disabled: "bg-[#2a3144] text-muted",
	low: "bg-green-400 text-black",
	medium: "bg-yellow-400 text-black",
	high: "bg-red-400 text-black",
	// `[&&]` doubles the selector so this beats a row's `**:text-black!`
	critical: "bg-[#402023] text-white! [&&]:text-white!",
}

export type BadgeTone = keyof typeof tones

export const Badge = ({
	tone,
	children,
	...props
}: {
	tone: BadgeTone
	children: ReactNode
}) => {
	return (
		<span
			{...props}
			className={cn(
				"inline-block rounded-[5px] px-2 py-1.25 text-[10px] capitalize",
				tones[tone],
			)}
		>
			{children}
		</span>
	)
}
