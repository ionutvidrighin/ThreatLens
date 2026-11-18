import { type SubmitEvent, useEffect, useMemo, useRef, useState } from "react"
import { updateDetectionRuleSchema } from "@/api/schemas/detectionRules.schemas"
import { ApiError } from "@/api/setup/client"
import type { DetectionRule } from "@/api/types"
import { DETECTION_RULES, HTTP_STATUS } from "@/constants"
import { toast } from "@/notifications"
import { useUpdateDetectionRule } from "@/queries/detectionRulesQueries"
import { Button } from "./ui/Button"
import { CheckboxField, InputField, SelectField } from "./ui/Field"
import { PanelHeading } from "./ui/Panel"

const ruleSeverity = ["low", "medium", "high", "critical"]

/** The editable subset of a rule, as held in the form. */
type RuleDraft = Pick<
	DetectionRule,
	"enabled" | "threshold" | "windowSeconds" | "severity"
>

type EditRuleDialogProps = {
	ruleItem: DetectionRule
	onClose: () => void
	onReload: () => Promise<void>
}

export const EditRuleDialog = ({
	ruleItem,
	onClose,
	onReload,
}: EditRuleDialogProps) => {
	const dialog = useRef<HTMLDialogElement>(null)
	const ruleEnableToggle = useRef<HTMLInputElement>(null)

	const [ruleData, setRuleData] = useState<RuleDraft>({
		enabled: ruleItem.enabled,
		threshold: ruleItem.threshold,
		windowSeconds: ruleItem.windowSeconds,
		severity: ruleItem.severity,
	})

	const [reloading, setReloading] = useState(false)

	const {
		mutateAsync: handleRuleUpdate,
		error: ruleUpdateError,
		isPending: ruleUpdatePending,
	} = useUpdateDetectionRule()

	const isConflict =
		ruleUpdateError instanceof ApiError &&
		ruleUpdateError.status === HTTP_STATUS.CONFLICT

	const uncertain =
		ruleUpdateError instanceof TypeError ||
		(ruleUpdateError instanceof ApiError &&
			ruleUpdateError.status === HTTP_STATUS.UNPROCESSABLE_ENTITY)

	const reloadRequired = isConflict || uncertain
	const busy = ruleUpdatePending || reloading

	const isPasswordSprayingRule =
		ruleItem.ruleId === DETECTION_RULES.PASSWORD_SPRAYING
	const isCloudTrailTamperingRule =
		ruleItem.ruleId === DETECTION_RULES.CLOUDTRAIL_TAMPERING

	const showThresholdField = useMemo(
		() => !isCloudTrailTamperingRule,
		[ruleItem.ruleId],
	)
	const showWindowField = useMemo(
		() => !isCloudTrailTamperingRule,
		[ruleItem.ruleId],
	)

	const setField = <Key extends keyof RuleDraft>(
		field: Key,
		value: RuleDraft[Key],
	) => {
		return setRuleData((prev) => ({ ...prev, [field]: value }))
	}

	const submitForm = async (event: SubmitEvent<HTMLFormElement>) => {
		event.preventDefault()
		if (busy || reloadRequired) {
			return
		}

		// Send only the fields the user changed.
		const changedFields = Object.entries(ruleData).filter(
			([field, value]) => value !== ruleItem[field as keyof RuleDraft],
		)

		const validRuleUpdateData = updateDetectionRuleSchema.safeParse({
			...Object.fromEntries(changedFields),
			previouslyUpdatedAt: ruleItem.updatedAt,
		})

		if (!validRuleUpdateData.success) {
			toast.error(validRuleUpdateData.error.issues[0].message, {
				id: "rule-validation",
			})
			return
		}

		try {
			await handleRuleUpdate({
				ruleId: ruleItem.ruleId,
				updatedRule: validRuleUpdateData.data,
			})
			onClose()
		} catch {
			/* Mutation reports the error through a toast and keeps the form open. */
		}
	}

	useEffect(() => {
		dialog.current?.showModal()
		ruleEnableToggle.current?.focus()
	}, [])

	return (
		<dialog
			ref={dialog}
			className="m-auto max-h-[90vh] w-[min(560px,calc(100vw-32px))] overflow-auto rounded-[14px] border border-line-strong bg-surface p-0 text-ink shadow-[0_24px_80px_#00000099] backdrop:bg-black/60"
			aria-labelledby="edit-rule-title"
			onCancel={(event) => {
				event.preventDefault()
				if (!busy) onClose()
			}}
		>
			<form onSubmit={(event) => void submitForm(event)}>
				<PanelHeading
					titleId="edit-rule-title"
					title="Edit detection rule"
					description={ruleItem.ruleId}
					descriptionClassName="wrap-anywhere"
				>
					<Button disabled={busy} onClick={onClose} aria-label="Close editor">
						Close
					</Button>
				</PanelHeading>
				<fieldset
					disabled={busy || reloadRequired}
					className="m-0 grid gap-5.5 border-0 p-6.5"
				>
					<CheckboxField
						ref={ruleEnableToggle}
						label="Rule enabled"
						checked={ruleData.enabled}
						onChange={(event) => setField("enabled", event.target.checked)}
					/>
					{showThresholdField && (
						<InputField
							label="Threshold"
							hint={
								isPasswordSprayingRule
									? "Number of distinct accounts"
									: "Number of failed attempts"
							}
							type="number"
							required
							min="1"
							step="1"
							value={ruleData.threshold}
							onChange={(event) =>
								setField("threshold", Number(event.target.value))
							}
						/>
					)}

					{showWindowField && (
						<InputField
							label="Window (minutes)"
							type="number"
							required
							min="1"
							max="86400"
							step="1"
							value={(ruleData.windowSeconds ?? 0) / 60} // display in minutes
							onChange={
								(event) =>
									setField("windowSeconds", Number(event.target.value) * 60) // store in seconds
							}
						/>
					)}

					<SelectField
						label="Severity"
						options={ruleSeverity}
						value={ruleData.severity}
						onChange={(event) =>
							setField("severity", event.target.value as RuleDraft["severity"])
						}
					/>
				</fieldset>
				{reloadRequired && (
					<div
						className="mx-6.5 my-5 rounded-md border border-[#5a2a2d] bg-[#2d1b1f] p-4 text-[13px] leading-[1.7] text-[#f0a09a]"
						role="alert"
					>
						<p className="mb-3">
							{isConflict
								? "This rule has changed. Reload to replace this draft with the latest values."
								: "The save result is uncertain. Reload the rule before making another change."}
						</p>
						<Button
							disabled={busy}
							onClick={() => {
								setReloading(true)
								void onReload().finally(() => setReloading(false))
							}}
						>
							{reloading ? "Reloading..." : "Reload latest values"}
						</Button>
					</div>
				)}
				<div className="flex justify-end gap-3 border-t border-line-soft px-6.5 py-5">
					<Button disabled={busy} onClick={onClose}>
						Cancel
					</Button>
					<Button
						type="submit"
						variant="primary"
						disabled={busy || reloadRequired}
						aria-busy={ruleUpdatePending}
					>
						{ruleUpdatePending ? "Saving..." : "Save changes"}
					</Button>
				</div>
			</form>
		</dialog>
	)
}
