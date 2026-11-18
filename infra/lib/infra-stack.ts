import * as cdk from "aws-cdk-lib/core"
import type { Construct } from "constructs"
import { CONSTRUCT_IDS } from "./constants"
import { DynamoDBTables } from "./constructs/dynamoTables"
import { SQSqueues } from "./constructs/sqsQueues"
// import * as sqs from 'aws-cdk-lib/aws-sqs';

export class InfraStack extends cdk.Stack {
	constructor(scope: Construct, id: string, props?: cdk.StackProps) {
		super(scope, id, props)

		// The code that defines your stack goes here
		const tables = new DynamoDBTables(this, CONSTRUCT_IDS.dynamoDBtables.id)
		const sqsQueues = new SQSqueues(this, CONSTRUCT_IDS.sqsQueues.id)
	}
}
