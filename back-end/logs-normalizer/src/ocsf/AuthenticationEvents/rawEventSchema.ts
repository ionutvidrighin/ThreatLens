import z from "zod"
import { AUTHENTICATION_EVENT } from "../../constants"

export const RawAuthenticationEventSchema = z.object({
	eventId: z.string().min(1),

	eventType: z.literal(AUTHENTICATION_EVENT),

	eventTime: z.iso.datetime(),

	source: z.string().min(1),

	username: z.string().min(1),

	sourceIp: z.union([z.ipv4(), z.ipv6()]),

	outcome: z.literal(["success", "failure"]),
})
