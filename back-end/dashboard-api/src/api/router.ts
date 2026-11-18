import type {
	APIGatewayProxyEventV2,
	APIGatewayProxyStructuredResultV2,
} from "aws-lambda"
import { HTTP_STATUS } from "@/constants"
import { errorToResponse, jsonResponse } from "./httpHelpers"
import {
	fetchDetectionRules,
	updateSingleDetectionRule,
} from "./routes/detectionRules.routes"
import { fetchSecurityAlerts } from "./routes/securityAlerts.routes"

type RouteHandler = (
	event: APIGatewayProxyEventV2,
) => Promise<APIGatewayProxyStructuredResultV2>

const API_ROUTES: Record<string, RouteHandler> = {
	"GET /api/detection-rules": fetchDetectionRules,
	"PATCH /api/detection-rules/{ruleId}": updateSingleDetectionRule,
	"GET /api/security-alerts": fetchSecurityAlerts,
}

export const dispatch = async (event: APIGatewayProxyEventV2) => {
	const route = API_ROUTES[event.routeKey]
	if (!route) {
		return jsonResponse({
			statusCode: HTTP_STATUS.NOT_FOUND,
			body: { message: "Route not found" },
		})
	}

	try {
		return await route(event)
	} catch (error) {
		return errorToResponse(error)
	}
}
