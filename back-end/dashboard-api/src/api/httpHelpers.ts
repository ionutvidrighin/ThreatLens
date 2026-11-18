import type {
	APIGatewayProxyEventV2,
	APIGatewayProxyStructuredResultV2,
} from "aws-lambda"
import type { ZodType, z } from "zod"
import { HTTP_STATUS } from "@/constants"
import { ConflictError, HttpError, NotFoundError } from "@/errors"

type JsonResponseParams = {
	statusCode: number
	body: unknown
}

/**
 * Reads the JSON body of an API Gateway event.
 * API Gateway may base64-encode the body, and the body is absent when the
 * client sends none, so both cases are handled here, once, for every route.
 */
export const parseJsonBody = (event: APIGatewayProxyEventV2): unknown => {
	if (!event.body) {
		throw new HttpError(HTTP_STATUS.BAD_REQUEST, "Request body is required")
	}

	const text = event.isBase64Encoded
		? Buffer.from(event.body, "base64").toString("utf8")
		: event.body

	try {
		return JSON.parse(text)
	} catch {
		throw new HttpError(
			HTTP_STATUS.BAD_REQUEST,
			"Request body must be valid JSON",
		)
	}
}

export const parseOrThrow400 = <SchemaType extends ZodType>(
	schema: SchemaType,
	dataToValidate: unknown,
): z.infer<SchemaType> => {
	const result = schema.safeParse(dataToValidate)

	if (!result.success) {
		throw new HttpError(
			HTTP_STATUS.BAD_REQUEST,
			"Invalid request",
			result.error.issues,
		)
	}

	return result.data
}

export const jsonResponse = ({
	statusCode,
	body,
}: JsonResponseParams): APIGatewayProxyStructuredResultV2 => {
	return {
		statusCode,
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	}
}

export const errorToResponse = (
	error: unknown,
): APIGatewayProxyStructuredResultV2 => {
	if (error instanceof HttpError) {
		return jsonResponse({
			statusCode: error.statusCode,
			body: { message: error.message, issues: error.details },
		})
	}

	if (error instanceof NotFoundError) {
		return jsonResponse({
			statusCode: HTTP_STATUS.NOT_FOUND,
			body: { message: error.message },
		})
	}

	if (error instanceof ConflictError) {
		return jsonResponse({
			statusCode: HTTP_STATUS.CONFLICT,
			body: { message: error.message },
		})
	}

	console.error({ detail: "Unhandled error", error })
	return jsonResponse({
		statusCode: HTTP_STATUS.INTERNAL_SERVER_ERROR,
		body: { message: "Internal server error" },
	})
}
