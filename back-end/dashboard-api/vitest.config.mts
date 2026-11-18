import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

export default defineConfig({
	resolve: {
		alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
	},
	test: {
		include: ["tests/**/*.test.ts"],
		environment: "node",
		restoreMocks: true,
		// The default worker pools fail in this package with "Vitest failed to
		// find the runner" (cause not found; detection-engine is unaffected).
		pool: "vmThreads",
	},
})
