import { createHash } from "node:crypto"

export function isConditionalCheckFailure(error: unknown): boolean {
	return (
		error instanceof Error && error.name === "ConditionalCheckFailedException"
	)
}

export function createAlertId(
	ruleId: string,
	sourceIp: string,
	dedupeKey: string | number,
): string {
	const value = `${ruleId}:${sourceIp}:${dedupeKey}`

	const hash = createHash("sha256").update(value).digest("hex").slice(0, 24)

	return `alert-${hash}`
}
