// lib/constructs/dynamoTables.ts
import * as dynamodb from "aws-cdk-lib/aws-dynamodb"
import * as cdk from "aws-cdk-lib/core"
import { Construct } from "constructs"
import { CONSTRUCT_IDS } from "../constants"

export class DynamoDBTables extends Construct {
	public readonly detectionRules: dynamodb.Table
	public readonly authenticationFailures: dynamodb.Table
	public readonly securityAlerts: dynamodb.Table

	constructor(scope: Construct, id: string) {
		super(scope, id)

		this.detectionRules = new dynamodb.Table(
			this,
			CONSTRUCT_IDS.dynamoDBtables.detectionRulesTable,
			{
				partitionKey: {
					name: "ruleId",
					type: dynamodb.AttributeType.STRING,
				},
				billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
				removalPolicy: cdk.RemovalPolicy.RETAIN,
			},
		)

		this.authenticationFailures = new dynamodb.Table(
			this,
			CONSTRUCT_IDS.dynamoDBtables.authFailuresTable,
			{
				partitionKey: {
					name: "sourceIp",
					type: dynamodb.AttributeType.STRING,
				},
				sortKey: { name: "eventKey", type: dynamodb.AttributeType.STRING },
				timeToLiveAttribute: "expiresAt",
				billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
				removalPolicy: cdk.RemovalPolicy.DESTROY,
			},
		)

		this.securityAlerts = new dynamodb.Table(
			this,
			CONSTRUCT_IDS.dynamoDBtables.securityAlertsTable,
			{
				partitionKey: {
					name: "alertId",
					type: dynamodb.AttributeType.STRING,
				},
				billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
				removalPolicy: cdk.RemovalPolicy.RETAIN,
			},
		)

		for (const attribute of CONSTRUCT_IDS.dynamoDBtables
			.securityAlertsGlobalIndexes) {
			this.securityAlerts.addGlobalSecondaryIndex({
				indexName: `query-by-${attribute}`, // builds "query-by-ruleId", etc.
				partitionKey: { name: attribute, type: dynamodb.AttributeType.STRING },
				sortKey: { name: "createdAt", type: dynamodb.AttributeType.STRING },
				projectionType: dynamodb.ProjectionType.ALL,
			})
		}
	}
}
