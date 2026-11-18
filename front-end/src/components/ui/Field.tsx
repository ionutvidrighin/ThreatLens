import type { ComponentProps, ReactNode } from "react"
import { cn } from "@/lib/cn"

const controlClass =
	"w-full rounded-md border border-line-strong bg-field p-[11px] text-ink focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-focus"

type FieldProps = { label: string; hint?: ReactNode }

/**
 * Label that wraps its control, so no `id`/`htmlFor` pairing is needed.
 * `hint` is helper text shown under the control.
 */
const Field = ({
	label,
	hint,
	children,
}: {
	label: string
	hint?: ReactNode
	children: ReactNode
}) => {
	return (
		// biome-ignore lint/a11y/noLabelWithoutControl: the control is passed as `children`, so it is always nested inside this label
		<label className="grid gap-2 text-[13px] font-semibold">
			{label}
			{children}
			{hint && (
				<small className="block text-[10px] font-normal text-faint">
					{hint}
				</small>
			)}
		</label>
	)
}

export const InputField = ({
	label,
	hint,
	className,
	...props
}: FieldProps & ComponentProps<"input">) => {
	return (
		<Field label={label} hint={hint}>
			<input className={cn(controlClass, className)} {...props} />
		</Field>
	)
}

export const SelectField = ({
	label,
	hint,
	options,
	className,
	...props
}: FieldProps &
	Omit<ComponentProps<"select">, "children"> & {
		options: readonly string[]
	}) => {
	return (
		<Field label={label} hint={hint}>
			<select className={cn(controlClass, className)} {...props}>
				{options.map((option) => (
					<option key={option} value={option}>
						{option}
					</option>
				))}
			</select>
		</Field>
	)
}

export const CheckboxField = ({
	label,
	className,
	...props
}: Pick<FieldProps, "label"> & Omit<ComponentProps<"input">, "type">) => {
	return (
		<label className="flex items-center gap-2.5 text-[13px] font-semibold">
			<input
				type="checkbox"
				className={cn("size-4.5 accent-brand", className)}
				{...props}
			/>
			{label}
		</label>
	)
}
