import { useAuth } from "react-oidc-context"
import { OAUTH_SCOPE } from "@/constants"

/**
 * App-level view of the signed-in session.
 * The only place (besides the provider) that knows about react-oidc-context,
 * so components depend on this instead of the auth library.
 */
export const useSession = () => {
	const auth = useAuth()

	return {
		/** Session is being restored or a sign-in/out redirect is in progress. */
		isLoading: auth.isLoading || Boolean(auth.activeNavigator),
		isAuthenticated: auth.isAuthenticated,
		error: auth.error,
		/** Stable user id (Cognito `sub`). */
		userId: auth.user?.profile.sub,
		email: auth.user?.profile.email,
		canEditRules: Boolean(auth.user?.scopes.includes(OAUTH_SCOPE.RULES_WRITE)),
		signIn: () => auth.signinRedirect(),
		/** Clears the local session only; the Cognito logout redirect stays in the caller. */
		clearSession: () => auth.removeUser(),
	}
}
