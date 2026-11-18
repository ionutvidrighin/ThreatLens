// Generic domain errors. The HTTP layer maps each base class to one status
// code (errorToResponse), so a new resource only needs a subclass here.
export class NotFoundError extends Error {}

export class ConflictError extends Error {}

export class RuleNotFoundError extends NotFoundError {}

export class RuleUpdateConflictError extends ConflictError {}

export class HttpError extends Error {
	constructor(
		public readonly statusCode: number,
		message: string,
		public readonly details?: unknown,
	) {
		super(message)
	}
}
