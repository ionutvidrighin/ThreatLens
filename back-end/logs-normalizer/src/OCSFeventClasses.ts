export const OCSF_EVENT_CLASSES = {
	// OCSF Category 3: Identity & Access Management
	identityAndAccessManagement: {
		// https://schema.ocsf.io/classes/authentication
		authentication: {
			category_uid: 3,
			class_uid: 3002,

			activities: {
				logon: 1,
				logoff: 2,
			},

			statuses: {
				success: 1,
				failure: 2,
			},
		},

		// https://schema.ocsf.io/classes/account_change
		accountChange: {
			category_uid: 3,
			class_uid: 3001,
		},

		// https://schema.ocsf.io/classes/authorize_session
		authorizeSession: {
			category_uid: 3,
			class_uid: 3003,
		},

		// https://schema.ocsf.io/classes/entity_management
		entityManagement: {
			category_uid: 3,
			class_uid: 3004,
		},
	},

	// OCSF Category 6: Application Activity
	applicationActivity: {
		// https://schema.ocsf.io/classes/api_activity
		apiActivity: {
			category_uid: 6,
			class_uid: 6003,

			activities: {
				create: 1,
				read: 2,
				update: 3,
				delete: 4,
			},

			statuses: {
				success: 1,
				failure: 2,
			},
		},
	},
} as const
