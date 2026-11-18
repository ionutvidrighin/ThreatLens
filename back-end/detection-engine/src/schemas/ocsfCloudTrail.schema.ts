import z from "zod"
import { OCSF_EVENT_CLASSES } from "../detection-rules/OCSFeventClasses"

const API_ACTIVITY = OCSF_EVENT_CLASSES.applicationActivity.apiActivity

export const OCSFCloudTrailSchema = z
	.object({
		class_uid: z.literal(API_ACTIVITY.class_uid),
		category_uid: z.literal(API_ACTIVITY.category_uid),

		activity_id: z.literal([
			API_ACTIVITY.activities.create,
			API_ACTIVITY.activities.read,
			API_ACTIVITY.activities.update,
			API_ACTIVITY.activities.delete,
			0, // Unknown activity
			99, // Other activity
		]),

		type_uid: z.number().int().nonnegative(),

		time: z.number().int().nonnegative(),

		severity_id: z.number().int().nonnegative(),

		status_id: z.literal([
			API_ACTIVITY.statuses.success,
			API_ACTIVITY.statuses.failure,
			0, // Unknown
			99, // Other
		]),

		metadata: z.object({
			version: z.string().min(1),
			product: z.object({
				name: z.string().min(1),
				vendor_name: z.string().min(1),
			}),
			original_event_uid: z.string().min(1),
		}),

		actor: z.object({
			user: z.object({
				name: z.string().min(1).optional(),
				uid: z.string().min(1).optional(),
				type: z.string().min(1).optional(),
				account: z
					.object({
						uid: z.string().min(1),
					})
					.optional(),
			}),
		}),

		api: z.object({
			operation: z.string().min(1),
			service: z.object({
				name: z.string().min(1),
			}),
		}),

		cloud: z.object({
			region: z.string().min(1),
			account: z.object({
				uid: z.string().min(1),
			}),
		}),

		src_endpoint: z
			.object({
				ip: z.union([z.ipv4(), z.ipv6()]).optional(),
				name: z.string().min(1).optional(),
			})
			.optional(),

		raw_data: z.string().min(1),

		requestParameters: z
			.object({
				bucketName: z.string().min(1).optional(),
				Host: z.string().min(1).optional(),
			})
			.optional(),

		resources: z
			.array(
				z.object({
					uid: z.string().min(1).optional(),
					name: z.string().min(1).optional(),
					type: z.string().min(1).optional(),
				}),
			)
			.optional(),
	})
	.superRefine((event, ctx) => {
		if (event.type_uid !== event.class_uid * 100 + event.activity_id) {
			ctx.addIssue({
				code: "custom",
				path: ["type_uid"],
				message: "type_uid must match class_uid and activity_id",
			})
		}
	})
