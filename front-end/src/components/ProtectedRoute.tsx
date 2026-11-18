import { useRef, useState } from "react"
import { Outlet } from "react-router"
import { useSession } from "@/hooks/useSession"
import { toast } from "@/notifications"
import { SignInPanel } from "./SignInPanel"
import { emptyStateClass, Panel } from "./ui/Panel"

export function ProtectedRoute() {
	const session = useSession()

	const [signingIn, setSigningIn] = useState(false)

	const started = useRef(false)

	const signIn = async () => {
		if (started.current) {
			return
		}

		started.current = true
		setSigningIn(true)
		toast.dismiss("auth-error")

		try {
			await session.signIn()
		} catch {
			started.current = false
			setSigningIn(false)
			toast.error("Unable to start sign-in. Please try again.", {
				id: "auth-error",
			})
		}
	}

	if (session.isLoading)
		return (
			<Panel className={emptyStateClass} role="status">
				Connecting your session...
			</Panel>
		)

	if (!session.isAuthenticated) {
		return <SignInPanel signingIn={signingIn} onSignIn={signIn} />
	}

	return <Outlet />
}
