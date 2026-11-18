import { COMPONENT_NAME } from "../constants"

type Level = "log" | "warn" | "error"

const emit = (
	level: Level,
	action: string,
	fields: Record<string, unknown> = {},
) => {
	console[level](
		JSON.stringify({ component: COMPONENT_NAME, action, ...fields }),
	)
}

export const logger = {
	info: (action: string, fields?: Record<string, unknown>) =>
		emit("log", action, fields),
	warn: (action: string, fields?: Record<string, unknown>) =>
		emit("warn", action, fields),
	error: (action: string, fields?: Record<string, unknown>) =>
		emit("error", action, fields),
}
