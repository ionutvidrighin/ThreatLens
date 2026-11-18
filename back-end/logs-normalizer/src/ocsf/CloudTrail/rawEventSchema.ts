import { z } from "zod"

export const RawCloudTrailEventSchema = z.looseObject({
	eventID: z.string().min(1),

	eventTime: z.iso.datetime(),

	eventSource: z.string().min(1),

	eventName: z.string().min(1),

	eventType: z.literal("AwsApiCall"),

	eventCategory: z.literal("Management").optional(),

	managementEvent: z.literal(true).optional(),

	awsRegion: z.string().min(1),

	sourceIPAddress: z.string().min(1),

	userIdentity: z.looseObject({
		type: z.string().min(1),

		accountId: z
			.string()
			.regex(/^\d{12}$/)
			.optional(),

		arn: z.string().min(1).optional(),

		principalId: z.string().min(1).optional(),

		userName: z.string().min(1).optional(),
	}),

	readOnly: z.boolean().optional(),

	errorCode: z.string().min(1).optional(),

	errorMessage: z.string().optional(),

	requestParameters: z
		.object({
			bucketName: z.string().min(1).optional(),
			Host: z.string().min(1).optional(),
		})
		.optional(),

	// Resources the call acted on. Not present on every event.
	resources: z
		.array(
			z.looseObject({
				ARN: z.string().min(1).optional(),
				type: z.string().min(1).optional(),
			}),
		)
		.optional(),

	recipientAccountId: z
		.string()
		.regex(/^\d{12}$/)
		.optional(),
})

export type RawCloudTrailEvent = z.infer<typeof RawCloudTrailEventSchema>
