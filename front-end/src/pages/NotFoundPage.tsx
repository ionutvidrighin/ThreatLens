import { Link } from "react-router"
import { buttonClass } from "@/components/ui/Button"
import { emptyStateClass, Panel } from "@/components/ui/Panel"
import { Eyebrow, H1 } from "@/components/ui/Typography"
import { ROUTES } from "@/routes"

export function NotFoundPage() {
	return (
		<Panel className={emptyStateClass}>
			<Eyebrow>404</Eyebrow>
			<H1>Page not found</H1>
			<p>This page does not exist.</p>
			<Link className={buttonClass("primary")} to={ROUTES.OVERVIEW}>
				Go to dashboard
			</Link>
		</Panel>
	)
}
