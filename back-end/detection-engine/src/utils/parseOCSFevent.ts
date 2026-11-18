export type ParseResult = { success: true; data: unknown } | { success: false }

/** Pure JSON parsing */
export const parseOCSFevent = (body: string): ParseResult => {
	try {
		return { success: true, data: JSON.parse(body) }
	} catch (error) {
		if (!(error instanceof SyntaxError)) {
			throw error
		}

		return { success: false }
	}
}
