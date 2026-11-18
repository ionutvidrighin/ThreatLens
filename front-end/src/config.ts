import { z } from "zod"

const schema = z.object({
	apiBaseUrl: z.url(),
	authority: z.url(),
	clientId: z.string().min(1),
	cognitoDomain: z.url(),
	appUrl: z.url(),
	scope: z.string().min(1),
})

export const configuration = schema.safeParse({
	apiBaseUrl: import.meta.env.VITE_API_BASE_URL,
	authority: import.meta.env.VITE_COGNITO_AUTHORITY,
	clientId: import.meta.env.VITE_COGNITO_CLIENT_ID,
	cognitoDomain: import.meta.env.VITE_COGNITO_DOMAIN,
	appUrl: import.meta.env.VITE_APP_URL,
	scope: import.meta.env.VITE_OAUTH_SCOPE,
})

export type AppConfig = z.infer<typeof schema>
