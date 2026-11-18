import type { CloudWatchLogsEvent, EventBridgeEvent } from "aws-lambda"

export type EventSource = "CloudWatchLogs" | "EventBridge"

export type EventBridgeCloudTrailEvent = EventBridgeEvent<
	"AWS API Call via CloudTrail",
	CloudTrailEventType
>

export type CloudWatchAuthenticationEvent = CloudWatchLogsEvent

export type CommonIncomingEvent =
	| CloudWatchAuthenticationEvent
	| EventBridgeCloudTrailEvent

export type LogEvent = {
	id: string
	timestamp: number
	message: string
}

export type CloudWatchPayload = {
	messageType: "DATA_MESSAGE" | "CONTROL_MESSAGE"
	owner: string
	logGroup: string
	logStream: string
	logEvents?: LogEvent[]
}

export type AuthenticationEventType = {
	eventId: string
	eventType: "authentication"
	eventTime: string
	source: string
	username: string
	sourceIp: string
	outcome: "success" | "failure"
}

export type CloudTrailEventType = {
	eventID: string
	eventTime: string
	eventSource: string
	eventName: string
	eventType: "AwsApiCall"
	eventCategory?: "Management"
	managementEvent?: boolean
	awsRegion: string
	sourceIPAddress: string

	userIdentity: {
		type: string
		accountId?: string
		arn?: string
		principalId?: string
		userName?: string
		[key: string]: unknown
	}

	readOnly?: boolean
	errorCode?: string
	errorMessage?: string
	recipientAccountId?: string

	// Preserve additional CloudTrail properties
	[key: string]: unknown
}

export type RawEventEnvelope = {
	eventId: string
	sourceLogEventId?: string
	sourceLogGroup?: string
	sourceLogStream?: string
	ingestionTime: string
	rawEvent: AuthenticationEventType | CloudTrailEventType
}
