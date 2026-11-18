import { beforeEach, describe, expect, it, vi } from "vitest"
import { EVENT_DUPLICATE, EVENT_STORED } from "../../src/constants"
import { makeEvent } from "../helpers"

const { send } = vi.hoisted(() => ({ send: vi.fn() }))

vi.mock("@aws-sdk/lib-dynamodb", async (importActual) => ({
	...(await importActual<typeof import("@aws-sdk/lib-dynamodb")>()),
	DynamoDBDocumentClient: { from: () => ({ send }) },
}))

import {
	getRecentAuthFailuresByIp,
	storeAuthActivityFailure,
} from "../../src/repositories/authFailures"

beforeEach(() => {
	send.mockReset()
})

describe("storeAuthActivityFailure", () => {
	it("stores the failure with a duplicate-guard condition", async () => {
		send.mockResolvedValue({})
		const event = makeEvent({ username: "carol", id: "evt-x" })

		await expect(storeAuthActivityFailure(event)).resolves.toBe(EVENT_STORED)

		const input = send.mock.calls[0][0].input
		expect(input.TableName).toBe("test-auth-failures")
		expect(input.ConditionExpression).toBe("attribute_not_exists(sourceIp)")
		expect(input.Item).toMatchObject({
			sourceIp: event.src_endpoint.ip,
			eventId: "evt-x",
			username: "carol",
		})
		expect(input.Item.eventKey).toBe(
			`${new Date(event.time).toISOString()}#evt-x`,
		)
	})

	it("returns DUPLICATE when the item already exists", async () => {
		const error = new Error("exists")
		error.name = "ConditionalCheckFailedException"
		send.mockRejectedValue(error)

		await expect(storeAuthActivityFailure(makeEvent())).resolves.toBe(
			EVENT_DUPLICATE,
		)
	})

	it("rethrows any other DynamoDB error", async () => {
		const error = new Error("throttled")
		error.name = "ProvisionedThroughputExceededException"
		send.mockRejectedValue(error)

		await expect(storeAuthActivityFailure(makeEvent())).rejects.toThrow(
			"throttled",
		)
	})
})

describe("getRecentAuthFailuresByIp", () => {
	it("queries the IP and time window with a consistent read", async () => {
		send.mockResolvedValue({ Items: [] })

		await getRecentAuthFailuresByIp({ sourceIp: "203.0.113.10", windowStart: 1_000_000, windowEnd: 2_000_000 })

		const input = send.mock.calls[0][0].input
		expect(input.TableName).toBe("test-auth-failures")
		expect(input.ConsistentRead).toBe(true)
		expect(input.ExpressionAttributeValues[":ip"]).toBe("203.0.113.10")
		expect(input.ExpressionAttributeValues[":start"]).toBe(
			`${new Date(1_000_000).toISOString()}#`,
		)
		expect(input.ExpressionAttributeValues[":end"]).toBe(
			`${new Date(2_000_000).toISOString()}#￿`,
		)
	})

	it("clamps a negative window start to the epoch", async () => {
		send.mockResolvedValue({ Items: [] })

		await getRecentAuthFailuresByIp({ sourceIp: "203.0.113.10", windowStart: -5000, windowEnd: 1000 })

		expect(
			send.mock.calls[0][0].input.ExpressionAttributeValues[":start"],
		).toBe("1970-01-01T00:00:00.000Z#")
	})

	it("follows pagination and aggregates all pages", async () => {
		send
			.mockResolvedValueOnce({
				Items: [{ eventId: "1" }, { eventId: "2" }],
				LastEvaluatedKey: { sourceIp: "ip", eventKey: "k2" },
			})
			.mockResolvedValueOnce({ Items: [{ eventId: "3" }] })

		const result = await getRecentAuthFailuresByIp({ sourceIp: "ip", windowStart: 0, windowEnd: 1000 })

		expect(result.map((r) => r.eventId)).toEqual(["1", "2", "3"])
		expect(send).toHaveBeenCalledTimes(2)
		expect(send.mock.calls[1][0].input.ExclusiveStartKey).toEqual({
			sourceIp: "ip",
			eventKey: "k2",
		})
	})

	it("returns an empty list when DynamoDB returns no Items", async () => {
		send.mockResolvedValue({})
		await expect(getRecentAuthFailuresByIp({ sourceIp: "ip", windowStart: 0, windowEnd: 1000 })).resolves.toEqual(
			[],
		)
	})

	it("propagates query failures", async () => {
		send.mockRejectedValue(new Error("DynamoDB unavailable"))
		await expect(getRecentAuthFailuresByIp({ sourceIp: "ip", windowStart: 0, windowEnd: 1000 })).rejects.toThrow(
			"DynamoDB unavailable",
		)
	})
})
