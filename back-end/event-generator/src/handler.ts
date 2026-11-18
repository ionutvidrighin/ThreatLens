import { randomUUID } from "node:crypto"

type AuthSimulation = {
	username?: string
	sourceIp?: string
	success?: boolean
}

type HttpEvent = {
	body?: string | null
	isBase64Encoded?: boolean
}

export const handler = async (event: HttpEvent) => {
	let input: AuthSimulation

	try {
		const body = event.isBase64Encoded
			? Buffer.from(event.body ?? "", "base64").toString("utf8")
			: (event.body ?? "{}")

		input = JSON.parse(body)
	} catch {
		return {
			statusCode: 400,
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ error: "Invalid JSON body" }),
		}
	}

	if (
		typeof input !== "object" ||
		input === null ||
		typeof input.username !== "string" ||
		!/^[a-zA-Z0-9_.-]{1,64}$/.test(input.username) ||
		typeof input.success !== "boolean"
	) {
		return {
			statusCode: 400,
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ error: "Invalid authentication simulation" }),
		}
	}

	const securityEvent = {
		eventId: randomUUID(),
		eventType: "authentication",
		eventTime: new Date().toISOString(),
		source: "threatlens-demo-auth",
		username: input.username,
		sourceIp: "198.51.100.10",
		outcome: input.success ? "success" : "failure",
	}

	console.log(JSON.stringify(securityEvent))

	return {
		statusCode: 202,
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			message: "Simulation accepted",
			eventId: securityEvent.eventId,
		}),
	}
}
