import axios, { type AxiosRequestConfig } from "axios"
import type { UserManager } from "oidc-client-ts"
import { HTTP_STATUS } from "@/constants"

/** Error from any API call; `status` is the HTTP status code. */
export class ApiError extends Error {
	constructor(
		message: string,
		public readonly status: number,
	) {
		super(message)
		this.name = "ApiError"
	}
}

/**
 * Shared axios instance for the ThreatLens API.
 * `baseURL` and the bearer token are injected once by `initApiClient`,
 * so API functions and query hooks never need to receive them.
 */
export const apiClient = axios.create({
	headers: { Accept: "application/json" },
})

export const initApiClient = async (
	baseUrl: string,
	userManager: UserManager,
) => {
	apiClient.defaults.baseURL = baseUrl.replace(/\/$/, "")

	apiClient.interceptors.request.clear()

	apiClient.interceptors.request.use(async (request) => {
		// Read at request time so silently renewed tokens are always used.
		const user = await userManager.getUser()
		if (!user || user.expired) {
			throw new Error("Sign in to continue.")
		}

		request.headers.set("Authorization", `Bearer ${user.access_token}`)
		return request
	})
}

export const handleAPIerror = (error: unknown) => {
	if (axios.isCancel(error) || !axios.isAxiosError(error)) {
		throw error
	}

	const status = error.response?.status

	if (status === undefined) {
		throw new TypeError("Could not reach the rules API.")
	}

	const messages: Record<number, string> = {
		[HTTP_STATUS.UNAUTHORIZED]:
			"Your session has expired. Sign out and sign in again.",
		[HTTP_STATUS.FORBIDDEN]:
			"Your account does not have permission to perform this update.",
		[HTTP_STATUS.CONFLICT]:
			"This entity changed since you opened it. Reload the latest values before editing again.",
		[HTTP_STATUS.BAD_REQUEST]:
			"The update was rejected. Check the field values and try again.",
		[HTTP_STATUS.NOT_FOUND]:
			"This entity no longer exists. Please reload the page.",
	}

	throw new ApiError(
		messages[status] ?? `Request failed (HTTP ${status}). Please retry.`,
		status,
	)
}

/** Returns the response body. `T` is unchecked; validate it (e.g. with Zod). */
export const Get_Request = async <T = unknown>(
	endpoint: string,
	config?: AxiosRequestConfig,
): Promise<T> => {
	const response = await apiClient.get<T>(endpoint, config)
	return response.data
}

export const Patch_Request = async <T = unknown>(
	endpoint: string,
	payload: unknown,
	config?: AxiosRequestConfig,
): Promise<T> => {
	const response = await apiClient.patch<T>(endpoint, payload, config)
	return response.data
}
