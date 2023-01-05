import pulumi
import pulumi_aws_native as aws_native
import pulumi_aws as aws
import json
from pulumi import ResourceOptions
import random

# declaring env variables

STACK_NAME = "org-tagging-compliance"
REGION_LIST = ["ap-southeast-2", "us-east-2", "us-east-1"]
ORGANIZATION_UNIT_ID = "ou-xxxxxxxxxxxx"
PERMISSION_MODEL = "SERVICE_MANAGED"
PARAMETER_KEY = "SNSTopicSubscriptionEmail"
PARAMETER_VALUE = "abc@xyz.com
TAG_KEYS = '{"tag1Key": "project","tag2Key": "customer"}'
RESOURCE_TYPES_SCOPES = [
    "AWS::S3::Bucket",
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::Volume",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::NatGateway",
    "AWS::EC2::EIP",
    "AWS::ECR::Repository",
    "AWS::EFS::FileSystem",
    "AWS::EKS::Cluster",
    "AWS::EKS::FargateProfile",
    "AWS::Kinesis::Stream",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBSnapshot",
    "AWS::RDS::DBCluster",
    "AWS::RDS::DBInstance",
    "AWS::Route53::HostedZone",
    "AWS::Route53Resolver::ResolverEndpoint",
    "AWS::Route53Resolver::ResolverRule",
    "AWS::SNS::Topic",
    "AWS::SQS::Queue",
    "AWS::EC2::Subnet",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::Backup::BackupPlan",
    "AWS::Backup::BackupVault",
    "AWS::ACM::Certificate",
    "AWS::CloudFormation::Stack",
    "AWS::CloudTrail::Trail",
    "AWS::CodeBuild::Project",
    "AWS::CodePipeline::Pipeline",
    "AWS::DMS::ReplicationInstance",
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::KMS::Key",
    "AWS::KMS::Alias",
    "AWS::Lambda::Function",
    "AWS::NetworkFirewall::Firewall",
    "AWS::SecretsManager::Secret",
    "AWS::WAFv2::WebACL",
    "AWS::WAFv2::Rule",
    "AWS::WAFv2::ManagedRuleSet",
    "AWS::WAFRegional::Rule",
    "AWS::WAFRegional::WebACL",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
]

############################################################################################
# creating a function to deploy organization config rule


def org_tagging_compliance_config_rule(REGION, RULE_IDENTIFIER):
    aws.cfg.OrganizationManagedRule(
        f"{STACK_NAME}-cfg-rule-" + REGION,
        rule_identifier=RULE_IDENTIFIER,
        resource_types_scopes=RESOURCE_TYPES_SCOPES,
        input_parameters=TAG_KEYS,
        opts=ResourceOptions(
            provider=aws.Provider(f"{STACK_NAME}-provider-" + REGION, region=REGION)
        ),
    )


############################################################################################
# creating a function to create cloudformation stackset which deploys lambda role


def org_tagging_compliance_lambda_role():
    aws_native.cloudformation.StackSet(
        f"{STACK_NAME}-lambda-role",
        permission_model=PERMISSION_MODEL,
        stack_set_name=f"{STACK_NAME}-lambda-role",
        auto_deployment=aws_native.cloudformation.StackSetAutoDeploymentArgs(
            enabled=True, retain_stacks_on_account_removal=True
        ),
        capabilities=[
            aws_native.cloudformation.StackSetCapability("CAPABILITY_NAMED_IAM")
        ],
        stack_instances_group=[
            aws_native.cloudformation.StackSetStackInstancesArgs(
                regions=[REGION_LIST[0]],
                deployment_targets=aws_native.cloudformation.StackSetDeploymentTargetsArgs(
                    organizational_unit_ids=[ORGANIZATION_UNIT_ID]
                ),
            )
        ],
        template_body="""
Resources:
  OrgRequiredTagsLambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Action: sts:AssumeRole
            Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Sid: ""
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      RoleName: org-tagging-compliance-lambda-role
  OrgRequiredTagsLambdaPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Action:
              - sns:Publish
            Effect: Allow
            Resource: "*"
      PolicyName: org-tagging-compliance-lambda-policy
      Roles:
        - !Ref OrgRequiredTagsLambdaRole
        """,
    )


############################################################################################
# creating a function to create cloudformation stackset which deploys tagging compliance stack


def org_tagging_compliance_stack():
    aws_native.cloudformation.StackSet(
        f"{STACK_NAME}-stack",
        permission_model=PERMISSION_MODEL,
        stack_set_name=f"{STACK_NAME}-stack",
        auto_deployment=aws_native.cloudformation.StackSetAutoDeploymentArgs(
            enabled=True, retain_stacks_on_account_removal=True
        ),
        capabilities=[
            aws_native.cloudformation.StackSetCapability("CAPABILITY_NAMED_IAM")
        ],
        stack_instances_group=[
            aws_native.cloudformation.StackSetStackInstancesArgs(
                regions=REGION_LIST,
                deployment_targets=aws_native.cloudformation.StackSetDeploymentTargetsArgs(
                    organizational_unit_ids=[ORGANIZATION_UNIT_ID]
                ),
            )
        ],
        parameters=[
            aws_native.cloudformation.StackSetParameterArgs(
                parameter_key=PARAMETER_KEY,
                parameter_value=PARAMETER_VALUE,
            )
        ],
        template_body="""
Parameters:
  SNSTopicSubscriptionEmail:
    Type: String
    Description: Email address for SNS topic subscription.
Resources:
  OrgRequiredTagsSnsTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: org-tagging-compliance-sns
  OrgRequiredTagsSnsTopicSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      Endpoint: !Ref SNSTopicSubscriptionEmail
      Protocol: email
      TopicArn: !Ref OrgRequiredTagsSnsTopic
  OrgRequiredTagsSnsTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Action:
              - SNS:Publish
            Effect: Allow
            Principal:
              Service:
                - events.amazonaws.com
                - lambda.amazonaws.com
            Resource: !Ref OrgRequiredTagsSnsTopic
      Topics:
        - !Ref OrgRequiredTagsSnsTopic
  OrgRequiredTagsLambda:
    Type: AWS::Lambda::Function
    Properties:
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref OrgRequiredTagsSnsTopic
      FunctionName: org-required-tagging-compliance-lambda
      Handler: index.lambda_handler
      Role: !Sub arn:aws:iam::${AWS::AccountId}:role/org-tagging-compliance-lambda-role
      Runtime: python3.9
      Code:
        ZipFile: |
          import json
          import boto3
          import logging
          import os

          logger = logging.getLogger()
          logger.setLevel(logging.INFO)
          #setup ENV Variable
          SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
          def lambda_handler(event, context):
                logger.info(f'event: {event}')
                Account_ID = (event['detail']['awsAccountId'])
                Resource_ID = (event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceId'])
                Resource_Type = (event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceType'])
                Region = (event['detail']['awsRegion'])
                client = boto3.client('sns')
                response = client.publish(
                    TargetArn=SNS_TOPIC_ARN,
                    Message=('Following resource missing mandatory tag(s):'+ os.linesep + 'Resource ID:{}'.format(Resource_ID) + os.linesep + 'Account ID:{}'.format(Account_ID) + os.linesep + 'Resource Type: {}'.format(Resource_Type) + os.linesep + 'Region: {}'.format(Region)),
                    MessageStructure='string'
                )
                return {'statusCode': 200,'body': json.dumps(response)}
  OrgRequiredTagsLambdaInvocationPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !GetAtt OrgRequiredTagsLambda.Arn
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt OrgRequiredTags.Arn
  OrgRequiredTags:
    Type: AWS::Events::Rule
    Properties:
      Description: Captures resources creation with non-compliant tags
      EventPattern:
        source:
          - aws.config
        detail-type:
          - Config Rules Compliance Change
        detail:
          messageType:
            - ComplianceChangeNotification
          configRuleName:
            - prefix: OrgConfigRule-
            - prefix: OrgConfigRuleForTag-
      Name: organization-tagging-compliance-event-rule
      State: ENABLED
      Targets:
        - Arn: !GetAtt OrgRequiredTagsLambda.Arn
          Id: OrgRequiredTagsLambda
""",
    )


############################################################################################
# calling functions

for i in REGION_LIST:
    org_tagging_compliance_config_rule(i, RULE_IDENTIFIER="REQUIRED_TAGS")

org_tagging_compliance_lambda_role()
org_tagging_compliance_stack()
