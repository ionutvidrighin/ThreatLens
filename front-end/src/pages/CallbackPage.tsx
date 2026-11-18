import { Link, Navigate } from "react-router"
import { buttonClass } from "@/components/ui/Button"
import { emptyStateClass, Panel } from "@/components/ui/Panel"
import { H1 } from "@/components/ui/Typography"
import { useSession } from "@/hooks/useSession"
import { ROUTES } from "@/routes"

export function CallbackPage() {
	const session = useSession()

	if (session.isLoading)
		return (
			<Panel className={emptyStateClass} role="status">
				Completing sign-in...
			</Panel>
		)

	if (session.error)
		return (
			<Panel className={emptyStateClass}>
				<H1>Sign-in was not completed</H1>
				<p>Return to the dashboard to start a fresh sign-in.</p>
				<Link className={buttonClass("secondary")} to={ROUTES.OVERVIEW} replace>
					Return to dashboard
				</Link>
			</Panel>
		)

	if (session.isAuthenticated) return <Navigate to={ROUTES.OVERVIEW} replace />
	return (
		<Panel className={emptyStateClass}>
			<H1>No sign-in to complete</H1>
			<Link className={buttonClass("primary")} to={ROUTES.OVERVIEW} replace>
				Go to dashboard
			</Link>
		</Panel>
	)
}
