import {
	QueryCache,
	QueryClient,
	QueryClientProvider,
} from "@tanstack/react-query"
import { type ReactNode, useEffect, useState } from "react"
import { useSession } from "@/hooks/useSession"
import { rulesErrorMessage, toast } from "@/notifications"

const QuerySession = ({ children }: { children: ReactNode }) => {
	const [client] = useState(
		() =>
			new QueryClient({
					defaultOptions: {
						queries: {
							staleTime: 5 * 60 * 1000, // data counts as fresh for 5 minutes
							refetchOnMount: false, // don't refetch when a component mounts
						},
					},
				queryCache: new QueryCache({
					onError: (error) =>
						toast.error(rulesErrorMessage(error), { id: "rules-error" }),
					onSuccess: () => toast.dismiss("rules-error"),
				}),
			}),
	)

	useEffect(() => () => client.clear(), [client])

	return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

export const QueryProvider = ({ children }: { children: ReactNode }) => {
	const session = useSession()

	// A new session/user gets a fresh cache; access tokens never enter query keys.
	const sessionKey = session.isAuthenticated ? session.userId : "signed-out"

	return <QuerySession key={sessionKey}>{children}</QuerySession>
}
