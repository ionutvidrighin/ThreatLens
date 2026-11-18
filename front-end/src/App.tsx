import { Navigate, Route, Routes } from "react-router"
import { AppLayout } from "./components/AppLayout"
import { ProtectedRoute } from "./components/ProtectedRoute"
import type { AppConfig } from "./config"
import { CallbackPage } from "./pages/CallbackPage"
import { DetectionRulesPage } from "./pages/DetectionRulesPage"
import { NotFoundPage } from "./pages/NotFoundPage"
import { OverviewPage } from "./pages/OverviewPage"
import { SecurityAlertsPage } from "./pages/SecurityAlertsPage"
import { ROUTES } from "./routes"

export const App = ({ config }: { config: AppConfig }) => {
	return (
		<Routes>
			<Route element={<AppLayout config={config} />}>
				<Route index element={<Navigate to={ROUTES.OVERVIEW} replace />} />
				<Route path={ROUTES.CALLBACK} element={<CallbackPage />} />
				<Route element={<ProtectedRoute />}>
					<Route path={ROUTES.OVERVIEW} element={<OverviewPage />} />
					<Route
						path={ROUTES.DETECTION_RULES}
						element={<DetectionRulesPage />}
					/>
					<Route
						path={ROUTES.SECURITY_ALERTS}
						element={<SecurityAlertsPage />}
					/>
				</Route>
				<Route path="*" element={<NotFoundPage />} />
			</Route>
		</Routes>
	)
}
