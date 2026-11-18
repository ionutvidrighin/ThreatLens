// lib/constructs/dynamoTables.ts
import * as dynamodb from "aws-cdk-lib/aws-dynamodb"
import * as cdk from "aws-cdk-lib/core"
import { Construct } from "constructs"
import { CONSTRUCT_IDS } from "../constants"

export class DynamoDBTables extends Construct {
	public readonly detectionRules: dynamodb.Table
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
	}
}
