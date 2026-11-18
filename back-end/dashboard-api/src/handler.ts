import type { APIGatewayProxyEventV2 } from "aws-lambda"
import { dispatch } from "./api/router"

export const handler = (event: APIGatewayProxyEventV2) => {
	return dispatch(event)
}
