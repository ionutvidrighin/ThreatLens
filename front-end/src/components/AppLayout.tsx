import { useEffect, useRef } from "react"
import { Outlet, useNavigate } from "react-router"
import type { AppConfig } from "@/config"
import { useSession } from "@/hooks/useSession"
import { cn } from "@/lib/cn"
import { toast } from "@/notifications"
import { ROUTES } from "@/routes"
import { AppHeader } from "./AppHeader"
import { Sidebar } from "./Sidebar"

export const AppLayout = ({ config }: { config: AppConfig }) => {
	const session = useSession()
	const navigate = useNavigate()
	const lastAuthError = useRef<Error | undefined>(undefined)

	const signOut = async () => {
		try {
			await session.clearSession()
			const url = new URL("/logout", config.cognitoDomain)
			url.searchParams.set("client_id", config.clientId)
			url.searchParams.set(
				"logout_uri",
				new URL(ROUTES.HOME, config.appUrl).href,
			)
			window.location.assign(url.href)
		} catch {
			toast.error("Unable to sign out. Please try again.", {
				id: "sign-out-error",
			})
		}
	}

	useEffect(() => {
		if (!session.error || lastAuthError.current === session.error) {
			return
		}

		lastAuthError.current = session.error

		toast.error("Sign-in could not be completed. Please try again.", {
			id: "auth-error",
			action: {
				label: "Return to dashboard",
				onClick: () => {
					void navigate(ROUTES.OVERVIEW, { replace: true })
				},
			},
		})
	}, [session.error, navigate])

	return (
		// The shell fills the viewport; only the content column scrolls.
		<div className="flex h-dvh flex-col overflow-hidden">
			<AppHeader
				isAuthenticated={session.isAuthenticated}
				email={session.email}
				onSignOut={signOut}
			/>
			<div
				className={cn(
					"grid min-h-0 flex-1 grid-rows-[minmax(0,1fr)]",
					session.isAuthenticated
						? "grid-cols-[240px_minmax(0,1fr)] max-[1100px]:grid-cols-[210px_minmax(0,1fr)] max-[760px]:flex max-[760px]:flex-col"
						: "grid-cols-[minmax(0,1fr)]",
				)}
			>
				{session.isAuthenticated && <Sidebar />}
				{/* `relative` makes this the containing block for absolutely positioned
				    children (e.g. `sr-only` table captions); otherwise they extend the
				    document and add an outer page scrollbar. */}
				<div className="relative flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto">
					<main className="mx-auto w-full max-w-330 flex-1 px-[clamp(22px,3vw,48px)] pt-10 pb-[54px] max-[760px]:px-5 max-[760px]:pt-7 max-[760px]:pb-10">
						<Outlet />
					</main>
					<footer className="flex shrink-0 justify-between border-t border-line px-[clamp(22px,3vw,48px)] py-[22px] text-[11px] text-muted">
						ThreatLens{" "}
						<span className="text-faint max-[700px]:hidden">
							Authentication monitoring & detection
						</span>
					</footer>
				</div>
			</div>
		</div>
	)
}
