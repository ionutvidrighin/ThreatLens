import { createRoot } from "react-dom/client"
import { BrowserRouter } from "react-router"
import { Toaster } from "sonner"
import { App } from "./App"
import { initApiClient } from "./api/setup/client"
import { createUserManager } from "./auth"
import { RouterAuthProvider } from "./components/RouterAuthProvider"
import { Eyebrow, H1 } from "./components/ui/Typography"
import { configuration } from "./config"
import { QueryProvider } from "./queries/QueryProvider"
import "./styles.css"

const rootElement = document.getElementById("root")
if (!rootElement) {
	throw new Error("Missing application root element")
}

const root = createRoot(rootElement)

// Inform about missing env vars
if (!configuration.success) {
	root.render(
		<main className="mx-auto my-20 max-w-162.5 px-[5vw] leading-[1.8]">
			<Eyebrow>THREATLENS</Eyebrow>
			<H1>Connect your dashboard</H1>
			<p>
				Copy <code>.env.example</code> to <code>.env.local</code>, review the
				connection settings, then restart the development server.
			</p>
			<p>See the project README for Cognito and API Gateway setup.</p>
		</main>,
	)
} else {
	const userManager = createUserManager(configuration.data)

	initApiClient(configuration.data.apiBaseUrl, userManager)

	root.render(
		<BrowserRouter>
			<RouterAuthProvider userManager={userManager}>
				<Toaster
					theme="dark"
					position="top-right"
					richColors
					closeButton
					duration={6000}
				/>
				<QueryProvider>
					<App config={configuration.data} />
				</QueryProvider>
			</RouterAuthProvider>
		</BrowserRouter>,
	)
}
