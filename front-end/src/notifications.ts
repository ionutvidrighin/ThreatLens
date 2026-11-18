export { toast } from "sonner"

export function rulesErrorMessage(error: unknown): string {
	if (error instanceof TypeError) {
		return "Could not reach the rules API. Check your connection or contact your administrator."
	}

	return error instanceof Error ? error.message : "Unable to load rules."
}
