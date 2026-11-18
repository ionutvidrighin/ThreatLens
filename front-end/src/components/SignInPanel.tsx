import { Button } from "./ui/Button"
import { Panel } from "./ui/Panel"
import { Eyebrow } from "./ui/Typography"

export function SignInPanel({
	signingIn,
	onSignIn,
}: {
	signingIn: boolean
	onSignIn: () => Promise<void>
}) {
	return (
		<Panel className="mx-auto my-12.5 max-w-212.5 px-6 pt-15 pb-18 text-center max-[700px]:my-5 max-[700px]:px-5 max-[700px]:py-10">
			<span
				className="mx-auto mb-7 grid size-17.5 place-items-center rounded-[20px] bg-accent-teal/15 text-[35px] text-accent-teal"
				aria-hidden="true"
			>
				&#9672;
			</span>
			<Eyebrow>YOUR SECURITY WORKSPACE</Eyebrow>
			<h2 className="my-3 font-display text-[30px] font-bold tracking-[-1px] text-heading max-[700px]:text-[25px]">
				Visibility starts here.
			</h2>
			<p className="mx-auto mb-7.5 max-w-105 text-sm leading-[1.8] text-muted">
				Sign in to view your authentication detection rules and their current
				configuration.
			</p>
			<Button
				variant="primary"
				disabled={signingIn}
				aria-busy={signingIn}
				onClick={() => void onSignIn()}
			>
				{signingIn ? "Redirecting to sign-in..." : "Sign in to ThreatLens"}
				<span aria-hidden="true">&#8594;</span>
			</Button>
		</Panel>
	)
}
