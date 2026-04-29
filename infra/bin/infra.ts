#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { MskStack } from '../lib/msk-stack';

const app = new cdk.App();

new MskStack(app, 'RtmMskStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region:  process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
  description: 'Real-time monitoring: MSK cluster + SSM exports for dashboard stack',
});
