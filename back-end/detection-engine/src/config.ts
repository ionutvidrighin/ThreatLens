const requireEnv = (name: string): string => {
	const value = process.env[name]

	if (!value) {
		throw new Error(`Missing ${name} environment variable`)
	}

	return value
}

// Fail fast at cold start if the Lambda is misconfigured.
export const config = {
	invalidEventsQueueUrl: requireEnv("INVALID_SQS_EVENTS_QUEUE_URL"),
} as const
