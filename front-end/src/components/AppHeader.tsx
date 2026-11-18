import { Shield } from "lucide-react"
import { Link } from "react-router"
import { ROUTES } from "@/routes"
import { Button } from "./ui/Button"

type AppHeaderProps = {
	isAuthenticated: boolean
	email?: string
	onSignOut: () => Promise<void>
}

export function AppHeader({
	isAuthenticated,
	email,
	onSignOut,
}: AppHeaderProps) {
	return (
		<header className="flex min-h-20.5 shrink-0 items-center justify-between gap-5 bg-nav px-[5vw] py-5 text-white">
			<Link
				className="flex items-center gap-3 font-display text-[23px] font-extrabold tracking-[-0.7px] no-underline max-[700px]:text-xl"
				to={ROUTES.OVERVIEW}
				aria-label="ThreatLens home"
			>
				<Shield
					size={28}
					strokeWidth={1.8}
					className="text-accent-blue"
					aria-hidden="true"
				/>
				ThreatLens
				<span className="mx-2 text-[#536179] max-[700px]:hidden">/</span>
				<span className="font-sans text-sm font-normal tracking-normal text-[#b6c2d3] max-[700px]:hidden">
					Administration
				</span>
			</Link>
			{isAuthenticated && (
				<div className="flex items-center gap-5 text-[13px]">
					<span className="max-[700px]:hidden">{email ?? "Administrator"}</span>
					<Button variant="ghost" onClick={() => void onSignOut()}>
						Sign out
					</Button>
				</div>
			)}
		</header>
	)
}
