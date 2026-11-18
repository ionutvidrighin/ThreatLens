import {
	UserManager,
	type UserManagerSettings,
	WebStorageStateStore,
} from "oidc-client-ts"
import type { AppConfig } from "./config"
import { ROUTES } from "./routes"

const createAuthSettings = (config: AppConfig): UserManagerSettings => {
	return {
		authority: config.authority,
		client_id: config.clientId,
		redirect_uri: new URL(ROUTES.CALLBACK, config.appUrl).href,
		response_type: "code",
		disablePKCE: false,
		scope: config.scope,
		userStore: new WebStorageStateStore({ store: window.sessionStorage }),
		stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
		automaticSilentRenew: true,
		monitorSession: false,
	}
}

export const createUserManager = (config: AppConfig): UserManager => {
	return new UserManager(createAuthSettings(config))
}
