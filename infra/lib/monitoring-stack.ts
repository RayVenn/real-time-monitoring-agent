import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as assets from 'aws-cdk-lib/aws-s3-assets';
import * as kfv2 from 'aws-cdk-lib/aws-kinesisanalyticsv2';
import * as logs from 'aws-cdk-lib/aws-logs';

/**
 * MonitoringStack provisions all AWS infrastructure for the real-time
 * network latency monitoring pipeline:
 *
 *   C++ agent (pcap)
 *     → MSK (net-latency, net-retransmit topics)
 *       → Amazon Managed Flink  (1-min windowed avg RTT per dst_ip)
 *         → Lambda (rtt-to-cloudwatch)
 *           → CloudWatch custom metric: Network/Latency / AvgRttUs
 *
 * Prerequisites before `cdk deploy`:
 *   cd flink-latency-job && ./gradlew shadowJar
 */
export class MonitoringStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ── VPC ──────────────────────────────────────────────────────────────────
    // Use the default VPC to avoid extra cost. MSK and Managed Flink both run
    // inside the VPC; the C++ agent connects via the MSK public endpoint.
    const vpc = ec2.Vpc.fromLookup(this, 'DefaultVpc', { isDefault: true });

    // ── Security groups ───────────────────────────────────────────────────────
    const mskSg = new ec2.SecurityGroup(this, 'MskSg', {
      vpc,
      description: 'MSK broker — allow Kafka from Flink and the local agent',
    });

    const flinkSg = new ec2.SecurityGroup(this, 'FlinkSg', {
      vpc,
      description: 'Managed Flink application',
    });

    // Flink → MSK (PLAINTEXT 9092, TLS 9094)
    mskSg.addIngressRule(flinkSg, ec2.Port.tcp(9092), 'Flink PLAINTEXT');
    mskSg.addIngressRule(flinkSg, ec2.Port.tcp(9094), 'Flink TLS');

    // Local agent → MSK public endpoint (TLS only)
    mskSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(9194), 'Agent public TLS');

    // ── MSK cluster ───────────────────────────────────────────────────────────
    // Single broker in one AZ — cheapest option (~$0.047/hr), no HA needed.
    // kafka.t3.small is the smallest supported instance type.
    const mskCluster = new msk.CfnCluster(this, 'MskCluster', {
      clusterName: 'net-monitor',
      kafkaVersion: '3.6.0',
      numberOfBrokerNodes: 1,

      brokerNodeGroupInfo: {
        instanceType: 'kafka.t3.small',
        clientSubnets: [vpc.publicSubnets[0].subnetId],
        securityGroups: [mskSg.securityGroupId],
        storageInfo: {
          ebsStorageInfo: { volumeSize: 10 },  // 10 GB minimum, ~$0.10/GB-month
        },
      },

      encryptionInfo: {
        encryptionInTransit: {
          // PLAINTEXT for intra-VPC (Flink), TLS for public endpoint (agent)
          clientBroker: 'TLS_PLAINTEXT',
          inCluster: true,
        },
      },

      // Enable public access so the local C++ agent can reach MSK over TLS
      // without needing a VPN or bastion host.
      clientAuthentication: {
        sasl: {
          iam: { enabled: true },
        },
        unauthenticated: { enabled: false },
      },

      openMonitoring: {
        prometheus: {
          jmxExporter:  { enabledInBroker: false },
          nodeExporter: { enabledInBroker: false },
        },
      },
    });

    // ── Lambda: rtt-to-cloudwatch ────────────────────────────────────────────
    const rttLambda = new lambda.Function(this, 'RttToCloudWatch', {
      functionName: 'rtt-to-cloudwatch',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(
        path.join(__dirname, '../../../real-time-monitoring-dashboard/lambda'),
      ),
      timeout: cdk.Duration.seconds(30),
      description: 'Receives windowed avg RTT from Flink and publishes to CloudWatch',
    });

    rttLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudwatch:PutMetricData'],
      resources: ['*'],
    }));

    // ── Flink JAR asset ──────────────────────────────────────────────────────
    // Build first: cd flink-latency-job && ./gradlew shadowJar
    const flinkJar = new assets.Asset(this, 'FlinkJar', {
      path: path.join(
        __dirname,
        '../../../real-time-monitoring-dashboard/flink-latency-job/build/libs/flink-latency-job.jar',
      ),
    });

    // ── IAM role for Managed Flink ───────────────────────────────────────────
    const flinkRole = new iam.Role(this, 'FlinkExecutionRole', {
      assumedBy: new iam.ServicePrincipal('kinesisanalytics.amazonaws.com'),
      description: 'Execution role for the network-latency Flink job',
    });

    rttLambda.grantInvoke(flinkRole);
    flinkJar.grantRead(flinkRole);

    flinkRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        // MSK IAM auth
        'kafka-cluster:Connect',
        'kafka-cluster:AlterCluster',
        'kafka-cluster:DescribeCluster',
        'kafka-cluster:DescribeTopic',
        'kafka-cluster:ReadData',
        'kafka-cluster:AlterGroup',
        'kafka-cluster:DescribeGroup',
      ],
      resources: [
        mskCluster.ref,
        `${mskCluster.ref}/*`,
      ],
    }));

    flinkRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        // VPC networking for Flink ENIs
        'ec2:DescribeVpcs',
        'ec2:DescribeSubnets',
        'ec2:DescribeSecurityGroups',
        'ec2:DescribeNetworkInterfaces',
        'ec2:CreateNetworkInterface',
        'ec2:CreateNetworkInterfacePermission',
        'ec2:DeleteNetworkInterface',
      ],
      resources: ['*'],
    }));

    flinkRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        'logs:CreateLogGroup',
        'logs:CreateLogDelivery',
        'logs:PutLogEvents',
        'logs:DescribeLogGroups',
        'logs:DescribeLogStreams',
      ],
      resources: ['*'],
    }));

    // ── CloudWatch log group for Flink ───────────────────────────────────────
    const flinkLogGroup = new logs.LogGroup(this, 'FlinkLogGroup', {
      logGroupName: '/aws/managed-flink/network-latency-job',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const flinkLogStream = new logs.LogStream(this, 'FlinkLogStream', {
      logGroup: flinkLogGroup,
      logStreamName: 'flink-job',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ── Amazon Managed Flink application ────────────────────────────────────
    const flinkApp = new kfv2.CfnApplication(this, 'LatencyFlinkApp', {
      applicationName: 'network-latency-job',
      runtimeEnvironment: 'FLINK-1_18',
      serviceExecutionRole: flinkRole.roleArn,

      applicationConfiguration: {
        applicationCodeConfiguration: {
          codeContent: {
            s3ContentLocation: {
              bucketArn: flinkJar.bucket.bucketArn,
              fileKey: flinkJar.s3ObjectKey,
            },
          },
          codeContentType: 'ZIPFILE',
        },

        environmentProperties: {
          propertyGroups: [{
            propertyGroupId: 'FlinkApplicationProperties',
            propertyMap: {
              // Flink reads MSK bootstrap brokers from this env var
              KAFKA_BROKERS:   cdk.Fn.join('', [
                'b-1.', mskCluster.ref, '.kafka.', this.region, '.amazonaws.com:9092',
              ]),
              AWS_REGION:      this.region,
              LAMBDA_FUNCTION: rttLambda.functionName,
            },
          }],
        },

        flinkApplicationConfiguration: {
          parallelismConfiguration: {
            configurationType: 'CUSTOM',
            parallelism: 1,
            parallelismPerKpu: 1,
            autoScalingEnabled: false,
          },
          checkpointConfiguration: {
            configurationType: 'DEFAULT',
          },
          monitoringConfiguration: {
            configurationType: 'CUSTOM',
            logLevel: 'INFO',
            metricsLevel: 'APPLICATION',
          },
        },

        // Flink runs inside the VPC to reach MSK over the private endpoint
        vpcConfigurations: [{
          subnetIds: [vpc.publicSubnets[0].subnetId],
          securityGroupIds: [flinkSg.securityGroupId],
        }],

        applicationSnapshotConfiguration: {
          snapshotsEnabled: false,
        },
      },
    });

    flinkApp.addDependency(mskCluster);

    new kfv2.CfnApplicationCloudWatchLoggingOption(this, 'FlinkLogging', {
      applicationName: 'network-latency-job',
      cloudWatchLoggingOption: {
        logStreamArn: `arn:aws:logs:${this.region}:${this.account}:log-group:${flinkLogGroup.logGroupName}:log-stream:${flinkLogStream.logStreamName}`,
      },
    });

    // ── Outputs ──────────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'MskClusterArn', {
      value: mskCluster.ref,
      description: 'MSK cluster ARN — use this as the Kafka bootstrap endpoint',
    });

    new cdk.CfnOutput(this, 'LambdaFunctionName', {
      value: rttLambda.functionName,
    });

    new cdk.CfnOutput(this, 'AgentRunCommand', {
      value: `sudo ./monitor-cpp/build/monitor --interface en0 --kafka-brokers <MSK_BOOTSTRAP_BROKERS>`,
      description: 'Replace <MSK_BOOTSTRAP_BROKERS> with the MSK public endpoint from the AWS console',
    });
  }
}
