import { z } from "zod"
import { OCSF_EVENT_CLASSES } from "../../OCSFeventClasses"

const AUTH_ACTIVITY =
	OCSF_EVENT_CLASSES.identityAndAccessManagement.authentication

export const OCSFAuthenticationSchema = z.object({
	class_uid: z.literal(AUTH_ACTIVITY.class_uid),
	category_uid: z.literal(AUTH_ACTIVITY.category_uid),
	activity_id: z.literal(AUTH_ACTIVITY.activities.logon),
	type_uid: z.number().int().nonnegative(),
	time: z.number().int().nonnegative(),
	severity_id: z.literal(1),
	status_id: z.literal([1, 2]),
	metadata: z.object({
		version: z.string().min(1),
		product: z.object({
			name: z.string().min(1),
			vendor_name: z.string().min(1),
		}),
		original_event_uid: z.string().min(1),
	}),
	user: z.object({
		name: z.string().min(1),
	}),
	src_endpoint: z.object({
		ip: z.union([z.ipv4(), z.ipv6()]),
	}),
	observables: z
		.array(
			z.object({
				name: z.string().min(1),
				type_id: z.int().nonnegative(),
				value: z.string().min(1),
			}),
		)
		.min(1),
	raw_data: z.string().min(1),
})

export type OCSFAuthenticationEvent = z.infer<typeof OCSFAuthenticationSchema>
