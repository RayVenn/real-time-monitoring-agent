import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as ssm from 'aws-cdk-lib/aws-ssm';

/**
 * MskStack provisions the MSK cluster and shared VPC for the real-time
 * network latency monitoring pipeline.
 *
 * Exports via SSM (consumed by dashboard-infra FlinkStack):
 *   /rtm/msk/brokers-iam       — SASL/IAM private bootstrap string  (port 9098)
 *   /rtm/msk/brokers-iam-public— SASL/IAM public  bootstrap string  (port 9198)
 *   /rtm/msk/cluster-arn       — full MSK cluster ARN
 *
 * Auth model:
 *   Go agent (local machine) → port 9198 (SASL/IAM public endpoint)
 *   Managed Flink (in-VPC)   → port 9098 (SASL/IAM private endpoint)
 */
export class MskStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ── VPC ──────────────────────────────────────────────────────────────────
    // Default VPC — brokers placed in a public subnet so the local Go agent
    // can reach the public MSK endpoint without a VPN.
    const vpc = ec2.Vpc.fromLookup(this, 'DefaultVpc', { isDefault: true });

    // ── Security groups ───────────────────────────────────────────────────────
    const mskSg = new ec2.SecurityGroup(this, 'MskSg', {
      vpc,
      securityGroupName: 'rtm-msk-sg',
      description: 'MSK broker security group',
    });

    // Flink (in-VPC) → private SASL/IAM endpoint
    mskSg.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(9098),
      'SASL/IAM private — Flink',
    );

    // Go agent (local) → public SASL/IAM endpoint
    // Scope to your IP in production; 0.0.0.0/0 is fine for dev/interview.
    mskSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(9198),
      'SASL/IAM public — Go agent',
    );

    // ── MSK cluster ───────────────────────────────────────────────────────────
    // Single broker in one AZ — cheapest viable option (~$0.047/hr for t3.small).
    // numberOfBrokerNodes must equal the number of distinct AZs in clientSubnets.
    const cluster = new msk.CfnCluster(this, 'Cluster', {
      clusterName: 'rtm-cluster',
      kafkaVersion: '3.6.0',
      numberOfBrokerNodes: 1,

      brokerNodeGroupInfo: {
        instanceType: 'kafka.t3.small',
        clientSubnets: [vpc.publicSubnets[0].subnetId],
        securityGroups: [mskSg.securityGroupId],
        storageInfo: {
          ebsStorageInfo: { volumeSize: 10 },
        },
        // Assign EIPs so the broker is reachable from outside AWS
        connectivityInfo: {
          publicAccess: { type: 'SERVICE_PROVIDED_EIPS' },
        },
      },

      clientAuthentication: {
        sasl: { iam: { enabled: true } },
        unauthenticated: { enabled: false },
      },

      encryptionInfo: {
        encryptionInTransit: {
          clientBroker: 'TLS',   // IAM auth requires TLS; no plaintext
          inCluster: true,
        },
      },

      openMonitoring: {
        prometheus: {
          jmxExporter:  { enabledInBroker: false },
          nodeExporter: { enabledInBroker: false },
        },
      },
    });

    // CfnCluster.getAtt() is used for bootstrap broker attributes because CDK's
    // typed attr* properties don't cover all MSK return values in every version.
    const brokersIam       = cluster.getAtt('BootstrapBrokersSaslIam').toString();
    const brokersIamPublic = cluster.getAtt('BootstrapBrokersSaslIamPublic').toString();

    // ── SSM exports ───────────────────────────────────────────────────────────
    // dashboard-infra/FlinkStack reads these at deploy time.
    new ssm.StringParameter(this, 'SsmBrokersIam', {
      parameterName: '/rtm/msk/brokers-iam',
      stringValue: brokersIam,
      description: 'MSK SASL/IAM private bootstrap (port 9098) — for Flink',
    });

    new ssm.StringParameter(this, 'SsmBrokersIamPublic', {
      parameterName: '/rtm/msk/brokers-iam-public',
      stringValue: brokersIamPublic,
      description: 'MSK SASL/IAM public bootstrap (port 9198) — for Go agent',
    });

    new ssm.StringParameter(this, 'SsmClusterArn', {
      parameterName: '/rtm/msk/cluster-arn',
      stringValue: cluster.ref,
      description: 'MSK cluster ARN',
    });

    // ── Outputs ───────────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'BrokersIamPublic', {
      value: brokersIamPublic,
      description: 'Pass to Go agent: --brokers <this> (port 9198)',
    });

    new cdk.CfnOutput(this, 'BrokersIam', {
      value: brokersIam,
      description: 'MSK private SASL/IAM brokers (port 9098) — for Flink/in-VPC clients',
    });

    new cdk.CfnOutput(this, 'ClusterArn', {
      value: cluster.ref,
    });
  }
}
