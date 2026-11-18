import type { UserManager } from "oidc-client-ts"
import type { ReactNode } from "react"
import { AuthProvider } from "react-oidc-context"
import { useLocation, useNavigate } from "react-router"
import { toast } from "@/notifications"
import { ROUTES } from "@/routes"

export function RouterAuthProvider({
	userManager,
	children,
}: {
	userManager: UserManager
	children: ReactNode
}) {
	const navigate = useNavigate()
	const location = useLocation()

	return (
		<AuthProvider
			userManager={userManager}
			skipSigninCallback={location.pathname !== ROUTES.CALLBACK}
			onSigninCallback={() => {
				// Replace the callback entry so the authorization code is removed from history.
				void navigate(ROUTES.OVERVIEW, { replace: true })
				toast.success("Signed in to ThreatLens", { id: "sign-in" })
			}}
		>
			{children}
		</AuthProvider>
	)
}
