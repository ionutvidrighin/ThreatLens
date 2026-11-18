import { defineConfig } from "vitest/config"

export default defineConfig({
	test: {
		include: ["tests/**/*.test.ts"],
		environment: "node",
		restoreMocks: true,
		// Pin configuration so tests are hermetic and independent of the shell.
		env: {
			INVALID_SQS_EVENTS_QUEUE_URL: "https://sqs.test/invalid-events",
			AUTH_FAILURES_DYNAMO_DB_TABLE: "test-auth-failures",
			SECURITY_ALERTS_DYNAMO_DB_TABLE: "test-security-alerts",
			BRUTE_FORCE_WINDOW_SECONDS: "300",
			BRUTE_FORCE_THRESHOLD: "5",
		},
	},
})
