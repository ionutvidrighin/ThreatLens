import z from "zod"
import { RawAuthenticationEventSchema } from "./AuthenticationEvents/rawEventSchema"
import { RawCloudTrailEventSchema } from "./CloudTrail/rawEventSchema"

export const CommonRawEventSchema = z.object({
	eventId: z.string().min(1),

	sourceLogEventId: z.string().min(1).optional(),
	sourceLogGroup: z.string().min(1).optional(),
	sourceLogStream: z.string().min(1).optional(),

	ingestionTime: z.iso.datetime(),

	rawEvent: z.discriminatedUnion("eventType", [
		RawAuthenticationEventSchema,
		RawCloudTrailEventSchema,
	]),
})

export type CommonRawEvent = z.infer<typeof CommonRawEventSchema>
