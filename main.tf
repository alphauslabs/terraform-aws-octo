provider "aws" {
  region     = "us-east-1"
  access_key = var.access_key != "" ? var.access_key : ""
  secret_key = var.secret_key != "" ? var.secret_key : ""
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_organizations_organization" "org" {}

locals {
  # Checking if current account is a master account
  isMaster = data.aws_caller_identity.current.account_id == data.aws_organizations_organization.org.master_account_id
}


resource "aws_iam_role" "octo_change_executor_role" {
  name = "OctoChangeExecutorRole"
  max_session_duration = 43200

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
          AWS     = "${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = ["sts:AssumeRole"]
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]
}

resource "aws_iam_role" "octo_ssm_updater_role" {
  name = "OctoSSMUpdaterRole"
  max_session_duration = 43200

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
        Principal = {
          AWS = var.principal
        }
      }
    ]
  })

  inline_policy {
    name = "OctoSSMUpdaterPolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = "iam:PassRole"
          Resource = aws_iam_role.octo_change_executor_role.arn
        },
        {
          Effect   = "Allow"
          Action   = [
            "ssm:StartChangeRequestExecution",
            "ssm:SendAutomationSignal",
            "ssm:CreateDocument"
          ]
          Resource = "*"
        }
      ]
    })
  }
}

resource "aws_iam_role" "octo_change_template_approver_role" {
  name = "OctoChangeTemplateApproverRole"
  max_session_duration = 43200

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = ["sts:AssumeRole"]
      }
    ]
  })

  inline_policy {
    name = "OctoChangeTemplateApproverPolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ssm:List*",
            "ssm:Get*",
            "ssm:Describe*",
            "ssm:UpdateDocumentMetadata",
            "ssm:UpdateDocument",
            "ssm:SendAutomationSignal"
          ]
          Resource = "*"
        }
      ]
    })
  }
}


# Alphaus account access role creation
resource "aws_iam_role" "alphaus_acct_access_role" {
  name                 = "AlphausAcctAccessRole"
  max_session_duration = 43200
  assume_role_policy   = data.aws_iam_policy_document.octo_assume_role.json

  inline_policy {
    name   = "root"
    policy = data.aws_iam_policy_document.root.json
  }
  inline_policy {
    name   = "octo-optimization-recommendation"
    policy = data.aws_iam_policy_document.octo-optimization-recommendation.json
  }
  path = "/"
}

data "aws_iam_policy_document" "octo_assume_role" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.principal]
    }

    condition {
      variable = "sts:ExternalId"
      test     = "StringEquals"
      values   = [var.external_id]
    }
  }
}

data "aws_iam_policy_document" "root" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "a4b:List*",
      "a4b:Search*",
      "acm:Describe*",
      "acm:List*",
      "acm-pca:Describe*",
      "acm-pca:List*",
      "amplify:ListApps",
      "amplify:ListBranches",
      "amplify:ListDomainAssociations",
      "amplify:ListJobs",
      "application-autoscaling:Describe*",
      "applicationinsights:Describe*",
      "applicationinsights:List*",
      "appmesh:Describe*",
      "appmesh:List*",
      "appstream:Describe*",
      "appstream:List*",
      "appsync:List*",
      "autoscaling-plans:Describe*",
      "athena:Batch*",
      "aws-portal:View*",
      "backup:Describe*",
      "backup:List*",
      "batch:List*",
      "batch:Describe*",
      "budgets:Describe*",
      "budgets:View*",
      "ce:Get*",
      "chatbot:Describe*",
      "chime:List*",
      "chime:Retrieve*",
      "chime:Search*",
      "chime:Validate*",
      "cloud9:Describe*",
      "cloud9:List*",
      "clouddirectory:List*",
      "cloudformation:Describe*",
      "cloudformation:ListResources",
      "cloudhsm:List*",
      "cloudhsm:Describe*",
      "cloudsearch:Describe*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudwatch:Describe*",
      "codeartifact:DescribeDomain",
      "codeartifact:DescribePackageVersion",
      "codeartifact:DescribeRepository",
      "codeartifact:ListDomains",
      "codeartifact:ListPackages",
      "codeartifact:ListPackageVersionAssets",
      "codeartifact:ListPackageVersionDependencies",
      "codeartifact:ListPackageVersions",
      "codeartifact:ListRepositories",
      "codeartifact:ListRepositoriesInDomain",
      "codebuild:DescribeCodeCoverages",
      "codebuild:DescribeTestCases",
      "codebuild:Get*",
      "codebuild:List*",
      "codebuild:BatchGetBuilds",
      "codebuild:BatchGetProjects",
      "codecommit:Describe*",
      "codeguru-profiler:Describe*",
      "codeguru-profiler:List*",
      "codeguru-reviewer:Describe*",
      "codeguru-reviewer:List*",
      "codepipeline:List*",
      "codepipeline:Get*",
      "codestar:Describe*",
      "config:Deliver*",
      "connect:Describe*",
      "dataexchange:List*",
      "datasync:Describe*",
      "datasync:List*",
      "datapipeline:Describe*",
      "datapipeline:List*",
      "detective:List*",
      "discovery:Describe*",
      "dms:Describe*",
      "dms:Test*",
      "ds:Check*",
      "ds:Describe*",
      "ds:List*",
      "ds:Verify*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "ec2:Describe*",
      "ec2:GetCapacityReservationUsage",
      "ec2:GetEbsEncryptionByDefault",
      "ec2:ModifyInstanceAttribute",
      "ec2:SearchTransitGatewayRoutes",
      "ec2:StartInstances",
      "ec2:StopInstances",
      "ec2:TerminateInstances",
      "ecr:BatchCheck*",
      "ecr:BatchGet*",
      "ecr:Describe*",
      "ecr:List*",
      "eks:DescribeCluster",
      "eks:DescribeUpdate",
      "eks:Describe*",
      "eks:ListClusters",
      "eks:ListUpdates",
      "eks:List*",
      "elasticache:List*",
      "elasticbeanstalk:Check*",
      "elasticbeanstalk:Describe*",
      "elasticbeanstalk:List*",
      "elasticbeanstalk:Request*",
      "elasticbeanstalk:Retrieve*",
      "elasticbeanstalk:Validate*",
      "elasticfilesystem:Describe*",
      "elasticloadbalancing:Describe*",
      "elasticmapreduce:Describe*",
      "elasticmapreduce:View*",
      "elastictranscoder:Read*",
      "elemental-appliances-software:List*",
      "es:Describe*",
      "es:List*",
      "es:ESHttpHead",
      "events:Describe*",
      "events:List*",
      "events:Test*",
      "firehose:Describe*",
      "fsx:Describe*",
      "fsx:List*",
      "freertos:Describe*",
      "freertos:List*",
      "glacier:Describe*",
      "globalaccelerator:Describe*",
      "globalaccelerator:List*",
      "glue:ListCrawlers",
      "glue:ListDevEndpoints",
      "glue:ListJobs",
      "glue:ListMLTransforms",
      "glue:ListTriggers",
      "glue:ListWorkflows",
      "guardduty:List*",
      "health:Describe*",
      "iam:Get*",
      "imagebuilder:List*",
      "importexport:List*",
      "inspector:Describe*",
      "inspector:Preview*",
      "iot:Describe*",
      "iotanalytics:Describe*",
      "iotanalytics:List*",
      "iotsitewise:Describe*",
      "iotsitewise:List*",
      "kafka:Describe*",
      "kafka:List*",
      "kinesisanalytics:Describe*",
      "kinesisanalytics:Discover*",
      "kinesisanalytics:List*",
      "kinesisvideo:Describe*",
      "kinesisvideo:List*",
      "kinesis:Describe*",
      "kinesis:List*",
      "kms:Describe*",
      "kms:List*",
      "license-manager:List*",
      "logs:ListTagsLogGroup",
      "logs:TestMetricFilter",
      "mediaconvert:DescribeEndpoints",
      "mediaconvert:List*",
      "mediapackage:List*",
      "mediapackage:Describe*",
      "medialive:List*",
      "medialive:Describe*",
      "mediaconnect:List*",
      "mediaconnect:Describe*",
      "mediapackage-vod:List*",
      "mediapackage-vod:Describe*",
      "mediastore:List*",
      "mediastore:Describe*",
      "mediatailor:List*",
      "mediatailor:Describe*",
      "mgh:Describe*",
      "mgh:List*",
      "mobilehub:Describe*",
      "mobilehub:List*",
      "mobiletargeting:List*",
      "mq:Describe*",
      "mq:List*",
      "opsworks-cm:List*",
      "organizations:Describe*",
      "outposts:List*",
      "personalize:Describe*",
      "personalize:List*",
      "pi:DescribeDimensionKeys",
      "polly:SynthesizeSpeech",
      "qldb:ListLedgers",
      "qldb:ListTagsForResource",
      "ram:List*",
      "rekognition:List*",
      "rds:List*",
      "redshift:Describe*",
      "redshift:View*",
      "resource-groups:Get*",
      "resource-groups:List*",
      "resource-groups:Search*",
      "robomaker:BatchDescribe*",
      "robomaker:Describe*",
      "robomaker:List*",
      "route53domains:Check*",
      "route53domains:Get*",
      "route53domains:View*",
      "s3:List*",
      "s3:GetBucketLocation",
      "s3:GetBucketTagging",
      "schemas:Describe*",
      "schemas:List*",
      "sdb:Select*",
      "secretsmanager:List*",
      "secretsmanager:Describe*",
      "securityhub:Describe*",
      "securityhub:List*",
      "serverlessrepo:List*",
      "servicecatalog:Scan*",
      "servicecatalog:Search*",
      "servicecatalog:Describe*",
      "servicediscovery:Get*",
      "servicediscovery:List*",
      "ses:Describe*",
      "shield:Describe*",
      "snowball:Describe*",
      "snowball:List*",
      "sns:Check*",
      "sqs:List*",
      "ssm:Describe*",
      "ssm:List*",
      "sso:Describe*",
      "sso:List*",
      "sso:Search*",
      "sso-directory:Describe*",
      "sso-directory:List*",
      "sso-directory:Search*",
      "states:List*",
      "states:Describe*",
      "storagegateway:Describe*",
      "storagegateway:List*",
      "sts:GetCallerIdentity",
      "sts:GetSessionToken",
      "swf:Describe*",
      "synthetics:Describe*",
      "synthetics:List*",
      "tag:Get*",
      "transfer:Describe*",
      "transfer:List*",
      "transcribe:List*",
      "wafv2:Describe*",
      "worklink:Describe*",
      "worklink:List*",
      "organizations:List*",
      "rds:DescribeReservedDBInstances",
      "elasticache:DescribeReservedCacheNodes",
      "es:DescribeReservedElasticsearchInstances",
      "redshift:DescribeReservedNodes",
      "savingsplans:DescribeSavingsPlan*",
      "cur:Describe*",
      "ce:Get*",
      "ce:List*",
      "billingconductor:List*",
      "cloudformation:Get*",
      "access-analyzer:List*",
      "amplify:List*",
      "apigateway:GET",
      "appflow:Describe*",
      "appflow:List*",
      "app-integrations:List*",
      "aps:List*",
      "autoscaling:Describe*",
      "databrew:List*",
      "firehose:List*",
      "route53resolver:List*",
      "ecs:Describe*",
      "ecs:List*",
      "fis:List*",
      "voiceid:List*",
      "network-firewall:List*",
      "refactor-spaces:List*",
      "athena:List*",
      "rds:Describe*",
      "signer:List*",
      "ssm:Get*",
      "lambda:List*",
      "rekognition:Describe*",
      "gamelift:List*",
      "emr-containers:List*",
      "lookoutmetrics:List*",
      "access-analyzer:Get*",
      "profile:List*",
      "iot:List*",
      "iot:Get*",
      "ssm-incidents:List*",
      "route53:List*",
      "ecr:Get*",
      "rolesanywhere:List*",
      "opsworks-cm:Describe*",
      "codestar-connections:List*",
      "rum:List*",
      "inspector:List*",
      "elasticache:Describe*",
      "cloudfront:List*",
      "elasticmapreduce:List*",
      "forecast:List*",
      "networkmanager:List*",
      "config:Describe*",
      "config:List*",
      "iotfleethub:List*",
      "ses:List*",
      "lookoutvision:List*",
      "fms:Get*",
      "fms:List*",
      "kafkaconnect:List*",
      "lakeformation:List*",
      "redshift-serverless:List*",
      "logs:Describe*",
      "iotdeviceadvisor:List*",
      "ivs:List*",
      "memorydb:Describe*",
      "sagemaker:List*",
      "servicecatalog:List*",
      "wafv2:List*",
      "greengrass:List*",
      "iam:List*",
      "airflow:List*",
      "cloudformation:List*",
      "cloudformation:BatchDescribe*",
      "iotevents:List*",
      "timestream:Describe*",
      "wisdom:List*",
      "lightsail:Get*",
      "route53:Get*",
      "athena:Get*",
      "ses:Get*",
      "lambda:Get*",
      "forecast:Describe*",
      "route53resolver:Get*",
      "networkmanager:Describe*",
      "memorydb:List*",
      "compute-optimizer:GetEC2InstanceRecommendations",
      "compute-optimizer:GetEC2RecommendationProjectedMetrics",
      "compute-optimizer:ExportEC2InstanceRecommendations",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "ce:StartSavingsPlansPurchaseRecommendationGeneration",
      "organizations:EnableAWSServiceAccess",
      "organizations:LeaveOrganization",
      "organizations:InviteAccountToOrganization",
      "organizations:AcceptHandshake",
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "iam:GetRole*",
      "iam:PutRolePolicy"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/AlphausAcctAccessRole"
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "iam:CreateServiceLinkedRole"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/cost-optimization-hub.bcm.amazonaws.com/AWSServiceRoleForCostOptimizationHub",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/trustedadvisor.amazonaws.com/AWSServiceRoleForTrustedAdvisor",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations"
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "iam:GetPolicy",
      "iam:GetPolicyVersion"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/AcctAccessManagedPolicy"
    ]
  }
}
# Octo optimization recommendation policy
data "aws_iam_policy_document" "octo-optimization-recommendation" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "trustedadvisor:Get*",
      "trustedadvisor:List*",
      "support:Describe*",
      "cost-optimization-hub:Get*",
      "cost-optimization-hub:List*",
      "cost-optimization-hub:Update*",
      "ec2:DeleteVolume",
      "ec2:DetachVolume",
      "ec2:DescribeVolumes",
      "lambda:DeleteFunction",
      "redshift:DeleteCluster",
      "es:DeleteDomain",
      "lambda:UpdateFunctionConfiguration",
      "ec2:ModifyVolume",
      "ec2:CreateSnapshot",
      "ec2:CreateImage",
      "iam:CreateRole",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "ec2:AssociateIamInstanceProfile",
      "iam:DeleteInstanceProfile",
      "ssm:SendCommand",
      "iam:AddRoleToInstanceProfile",
      "iam:PassRole",
      "ec2:ReleaseAddress",
      "rds:DeleteDBInstance",
      "rds:CreateDBSnapshot",
      "rds:AddTagsToResource",
      "elasticloadbalancing:DeleteLoadBalancer",
      "s3:PutLifecycleConfiguration",
      "s3:GetLifecycleConfiguration",
      "ecs:RegisterTaskDefinition",
      "ecs:UpdateService",
      "dlm:Get*",
      "secretsmanager:*",
      "ssm:*",
      "ssmmessages:*",
      "ec2messages:*",
      "ec2:RebootInstances",
      "cloudfront:GetCachePolicyConfig",
      "cloudtrail:LookupEvents",
      "kendra:List*",
      "kendra:Describe*",
      "quicksight:List*",
      "pricing:Get*",
      "pricing:ListPriceLists",
      "pricing:DescribeServices",
      "bedrock:List*",
      "bedrock:Get*",
    ]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "cloudsaver_policy_tagmanager" {
  name        = "CloudSaver-Policy-TagManager"
  description = "CloudSaver TagManager policy for AWS API. Version 1.0.27; Release Date 7/28/2023"
  policy      = data.aws_iam_policy_document.cloudsaver_policy_tag_manager_policy_document.json
}

data "aws_iam_policy_document" "cloudsaver_policy_tag_manager_policy_document" {
  version = "2012-10-17"
  statement {
    sid    = "CloudSaverTagManager"
    effect = "Allow"
    actions = [
      "access-analyzer:*tag*",
      "acm:*tag*",
      "appconfig:*tag*",
      "applicationinsights:*tag*",
      "appstream:*tag*",
      "appsync:*tag*",
      "athena:*tag*",
      "autoscaling:*tag*",
      "backup:*tag*",
      "braket:*tag*",
      "cassandra:*tag*",
      "cassandra:Alter",
      "cloud9:*tag*",
      "clouddirectory:*tag*",
      "cloudformation:*tag*",
      "cloudfront:*tag*",
      "cloudhsm:*tag*",
      "cloudtrail:*tag*",
      "cloudwatch:*tag*",
      "codeartifact:*tag*",
      "codecommit:*tag*",
      "codeguru-profiler:*tag*",
      "codeguru-reviewer:*tag*",
      "codepipeline:*tag*",
      "codestar:*tag*",
      "cognito-identity:*tag*",
      "cognito-idp:*tag*",
      "comprehend:*tag*",
      "config:*tag*",
      "databrew:*tag*",
      "dataexchange:*tag*",
      "datapipeline:*tag*",
      "datasync:*tag*",
      "dax:*tag*",
      "directconnect:*tag*",
      "dms:*tag*",
      "drs:*tag*",
      "ds:*tag*",
      "dynamodb:*tag*",
      "ec2:*tag*",
      "ecr-public:*tag*",
      "ecr:*tag*",
      "ecs:*tag*",
      "eks:*tag*",
      "elastic-inference:*tag*",
      "elasticache:*tag*",
      "elasticbeanstalk:*tag*",
      "elasticfilesystem:*tag*",
      "elasticloadbalancing:*tag*",
      "elasticmapreduce:*tag*",
      "emr-containers:*tag*",
      "es:*tag*",
      "evidently:*tag*",
      "firehose:*tag*",
      "forecast:*tag*",
      "frauddetector:*tag*",
      "fsx:*tag*",
      "glacier:*tag*",
      "glue:*tag*",
      "greengrass:*tag*",
      "imagebuilder:*tag*",
      "iot:*tag*",
      "iotanalytics:*tag*",
      "iotevents:*tag*",
      "iotsitewise:*tag*",
      "kafka:*tag*",
      "kendra:*tag*",
      "kinesis:*tag*",
      "kinesisanalytics:*tag*",
      "kinesisvideo:*tag*",
      "kms:*tag*",
      "lakeformation:*tag*",
      "lambda:*tag*",
      "logs:*tag*",
      "m2:*tag*",
      "macie2:*tag*",
      "mq:*tag*",
      "network-firewall:*tag*",
      "opsworks-cm:*tag*",
      "organizations:*tag*",
      "qldb:*tag*",
      "rds:*tag*",
      "redshift:*tag*",
      "resource-groups:*tag*",
      "robomaker:*tag*",
      "route53-recovery-control-config:*tag*",
      "route53-recovery-readiness:*tag*",
      "route53:*tag*",
      "route53domains:*tag*",
      "route53resolver:*tag*",
      "rum:*tag*",
      "s3-object-lambda:*tag*",
      "s3:GetBucketTagging",
      "s3:GetJobTagging",
      "s3:GetStorageLensConfigurationTagging",
      "s3:PutBucketTagging",
      "s3:PutJobTagging",
      "s3:PutStorageLensConfigurationTagging",
      "sagemaker:*tag*",
      "savingsplans:*tag*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "cloudsaver_policy_tagmanager2" {
  name        = "CloudSaver-Policy-TagManager2"
  description = "CloudSaver TagManager2 policy for AWS API. Version 1.0.27; Release Date 7/28/2023"
  policy      = data.aws_iam_policy_document.cloudsaver_policy_tagmanager2_policy_document.json
}

data "aws_iam_policy_document" "cloudsaver_policy_tagmanager2_policy_document" {
  version = "2012-10-17"
  statement {
    sid    = "CloudSaverTagManager2"
    effect = "Allow"
    actions = [
      "secretsmanager:*tag*",
      "securityhub:*tag*",
      "ses:*tag*",
      "sns:*tag*",
      "sqs:*tag*",
      "ssm:*tag*",
      "states:*tag*",
      "storagegateway:*tag*",
      "swf:*tag*",
      "synthetics:*tag*",
      "transfer:*tag*",
      "workspaces-web:*tag*",
      "workspaces:*tag*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "cloudsaver_policy_base" {
  name        = "CloudSaver-Policy-Base"
  description = "CloudSaver Base policy for AWS API. Version 1.0.27; Release Date 7/28/2023"
  policy      = data.aws_iam_policy_document.cloudsaver_policy_base_policy_document.json
}

data "aws_iam_policy_document" "cloudsaver_policy_base_policy_document" {
  version = "2012-10-17"
  statement {
    sid    = "CloudSaverBase"
    effect = "Allow"
    actions = [
      "account:GetAlternateContact",
      "account:GetContactInformation",
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "acm:ListTagsForCertificate",
      "apigateway:Get",
      "appstream:DescribeFleets",
      "appstream:DescribeImageBuilders",
      "appstream:DescribeImages",
      "appstream:DescribeStacks",
      "appstream:ListTagsForResource",
      "appsync:GetGraphqlApi",
      "appsync:ListGraphqlApis",
      "appsync:ListTagsForResource",
      "athena:GetWorkGroup",
      "athena:ListCapacityReservations",
      "athena:ListTagsForResource",
      "athena:ListWorkGroups",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "backup:DescribeBackupVault",
      "backup:DescribeFramework",
      "backup:DescribeRecoveryPoint",
      "backup:DescribeReportPlan",
      "backup:ListBackupPlans",
      "backup:ListBackupVaults",
      "backup:ListFrameworks",
      "backup:ListRecoveryPointsByBackupVault",
      "backup:ListRecoveryPointsByLegalHold",
      "backup:ListRecoveryPointsByResource",
      "backup:ListReportPlans",
      "backup:ListTags",
      "cassandra:Select",
      "ce:ListCostAllocationTags",
      "ce:UpdateCostAllocationTagsStatus",
      "clouddirectory:GetDirectory",
      "clouddirectory:ListDirectories",
      "clouddirectory:ListTagsForResource",
      "cloudfront:GetDistribution",
      "cloudfront:GetStreamingDistribution",
      "cloudfront:ListDistributions",
      "cloudfront:ListStreamingDistributions",
      "cloudfront:ListTagsForResource",
      "cloudhsm:DescribeBackups",
      "cloudhsm:DescribeClusters",
      "cloudtrail:DescribeTrails",
      "cloudtrail:ListTags",
      "cloudtrail:ListTrails",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStream",
      "cloudwatch:ListMetrics",
      "cloudwatch:ListMetricStreams",
      "cloudwatch:ListTagsForResource",
      "codepipeline:ListPipelines",
      "codepipeline:ListTagsForResource",
      "codestar:ListProjects",
      "codestar:ListTagsForProject",
      "cognito-identity:DescribeIdentityPool",
      "cognito-identity:ListIdentityPools",
      "cognito-identity:ListTagsForResource",
      "cognito-idp:DescribeUserPool",
      "cognito-idp:ListUserPools",
      "comprehend:DescribeFlywheel",
      "comprehend:ListFlywheels",
      "comprehend:ListTagsForResource",
      "cur:DescribeReportDefinitions",
      "datapipeline:DescribePipelines",
      "datapipeline:ListPipelines",
      "datasync:ListAgents",
      "datasync:ListLocations",
      "datasync:ListStorageSystems",
      "datasync:ListTagsForResource",
      "datasync:ListTasks",
      "dax:DescribeClusters",
      "dax:ListTags",
      "directconnect:DescribeConnections",
      "dms:DescribeEndpoints",
      "dms:DescribeEventSubscriptions",
      "dms:DescribeReplicationInstances",
      "dms:DescribeReplicationTasks",
      "dms:ListTagsForResource",
      "ds:DescribeDirectories",
      "ds:ListTagsForResource",
      "dynamodb:DescribeTable",
      "dynamodb:ListTables",
      "dynamodb:ListTagsOfResource",
      "ec2:DescribeAddresses",
      "ec2:DescribeFlowLogs",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceCreditSpecifications",
      "ec2:DescribeInstances",
      "ec2:DescribeNatGateways",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeReservedInstances",
      "ec2:DescribeSnapshots",
      "ec2:DescribeSpotInstanceRequests",
      "ec2:DescribeTransitGatewayAttachments",
      "ec2:DescribeTransitGateways"
    ]
    resources = ["*"]
  }
  statement {
    sid    = "CloudSaverApiS3Bucket"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:ListBucket",
      "s3:PutBucketPolicy",
      "s3:PutLifecycleConfiguration"
    ]
    resources = ["arn:aws:s3:::cloudsaver-${data.aws_caller_identity.current.account_id}-billing-files"]
  }
  statement {
    sid    = "CloudSaverApiS3BucketObjects"
    effect = "Allow"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject"
    ]
    resources = ["arn:aws:s3:::cloudsaver-${data.aws_caller_identity.current.account_id}-billing-files/*"]
  }
  statement {
    sid    = "CloudSaverApiSaveBillingReportToS3"
    effect = "Allow"
    actions = [
      "cur:DeleteReportDefinition",
      "cur:PutReportDefinition"
    ]
    resources = ["arn:aws:cur:*:*:definition/cloudsaver-${data.aws_caller_identity.current.account_id}-billing-files"]
  }
  statement {
    sid    = "CloudSaverApiSecretsManager"
    effect = "Allow"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmananger:DeleteSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecret"
    ]
    resources = [
      "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:events!connection/CloudSaverEventSourceConnection",
      "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:events!connection/CloudSaverEventSourceConnection/*",
      "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:events!api-destination/CloudSaverEventSourceApiDestination/*"
    ]
  }
  statement {
    sid    = "CloudSaverApiEvents"
    effect = "Allow"
    actions = [
      "events:CreateApiDestination",
      "events:CreateConnection",
      "events:DeleteApiDestination",
      "events:DeleteConnection",
      "events:InvokeApiDestination",
      "events:PutRule",
      "events:PutTargets"
    ]
    resources = [
      "arn:aws:events:*:${data.aws_caller_identity.current.account_id}:connection/*",
      "arn:aws:events:*:${data.aws_caller_identity.current.account_id}:api-destination/*",
      "arn:aws:events:*:${data.aws_caller_identity.current.account_id}:rule/*"
    ]
  }
  statement {
    sid       = "CloudSaverApiIamPassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CloudSaver-Role"]
  }
  statement {
    sid       = "CloudSaverApiCreateServiceLinkedRole"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/apidestinations.events.amazonaws.com/AWSServiceRoleForAmazonEventBridgeApiDestinations"]
  }
}

resource "aws_iam_policy" "cloudsaver_policy_base2" {
  name        = "CloudSaver-Policy-Base2"
  description = "CloudSaver Base2 policy for AWS API. Version 1.0.27; Release Date 7/28/2023"
  policy      = data.aws_iam_policy_document.cloudsaver_policy_base2_policy_document.json
}

data "aws_iam_policy_document" "cloudsaver_policy_base2_policy_document" {
  version = "2012-10-17"
  statement {
    sid    = "CloudSaverBase2"
    effect = "Allow"
    actions = [
      "ec2:DescribeVolumes",
      "ecr:DescribeRepositories",
      "ecr:ListTagsForResource",
      "ecs:DescribeClusters",
      "ecs:DescribeServices",
      "ecs:DescribeTasks",
      "ecs:ListClusters",
      "ecs:ListServices",
      "ecs:ListTasks",
      "eks:DescribeCluster",
      "eks:DescribeNodegroup",
      "eks:ListClusters",
      "eks:ListNodegroups",
      "elasticache:DescribeCacheClusters",
      "elasticache:DescribeReplicationGroups",
      "elasticache:DescribeSnapshots",
      "elasticache:ListTagsForResource",
      "elasticbeanstalk:DescribeApplications",
      "elasticbeanstalk:DescribeEnvironmentResources",
      "elasticbeanstalk:DescribeEnvironments",
      "elasticbeanstalk:ListTagsForResource",
      "elasticfilesystem:DescribeAccessPoints",
      "elasticfilesystem:DescribeFileSystems",
      "elasticfilesystem:ListTagsForResource",
      "elasticloadbalancing:DescribeInstanceHealth",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticmapreduce:DescribeCluster",
      "elasticmapreduce:ListClusters",
      "elasticmapreduce:ListInstances",
      "es:DescribeDomain",
      "es:ListDomainNames",
      "es:ListTags",
      "events:CreateConnection",
      "events:DescribeApiDestination",
      "events:DescribeConnection",
      "events:ListTargetsByRule",
      "events:UpdateApiDestination",
      "firehose:DescribeDeliveryStream",
      "firehose:ListDeliveryStreams",
      "firehose:ListTagsForDeliveryStream",
      "fsx:DescribeFileCaches",
      "fsx:DescribeFileSystems",
      "fsx:DescribeVolumes",
      "glacier:DescribeVault",
      "glacier:ListTagsForVault",
      "glacier:ListVaults",
      "glue:GetCrawler",
      "glue:GetJob",
      "glue:GetTags",
      "glue:ListCrawlers",
      "glue:ListJobs",
      "kafka:DescribeCluster",
      "kafka:DescribeClusterV2",
      "kafka:ListClusters",
      "kafka:ListClustersV2",
      "kafka:ListTagsForResource",
      "kafka:ListVpcConnections",
      "kendra:DescribeDataSource",
      "kendra:DescribeIndex",
      "kendra:ListDataSources",
      "kendra:ListIndices",
      "kendra:ListTagsForResource",
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
      "kinesis:ListTagsForStream",
      "kinesisanalytics:DescribeApplication",
      "kinesisanalytics:ListApplications",
      "kinesisanalytics:ListTagsForResource",
      "kms:DescribeKey",
      "kms:ListKeys",
      "kms:ListResourceTags",
      "lambda:GetFunction",
      "lambda:ListFunctions",
      "lambda:ListTags",
      "logs:DescribeLogGroups",
      "logs:ListTagsForResource",
      "m2:GetApplication",
      "m2:GetEnvironment",
      "m2:ListApplications",
      "m2:ListEnvironments",
      "m2:ListTagsForResource",
      "mq:DescribeBroker",
      "mq:DescribeConfiguration",
      "mq:ListBrokers",
      "mq:ListConfigurations",
      "network-firewall:ListFirewallPolicies",
      "network-firewall:ListFirewalls",
      "network-firewall:ListRuleGroups",
      "network-firewall:ListTagsForResource",
      "organizations:DescribeEffectivePolicy",
      "organizations:DescribeOrganizationalUnit",
      "organizations:DescribePolicy",
      "organizations:ListAccounts",
      "organizations:ListChildren",
      "organizations:ListPolicies",
      "organizations:ListRoots",
      "organizations:ListTargetsForPolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "cloudsaver_policy_base3" {
  name        = "CloudSaver-Policy-Base3"
  description = "CloudSaver Base3 policy for AWS API. Version 1.0.27; Release Date 7/28/2023"
  policy      = data.aws_iam_policy_document.cloudsaver_policy_base3_policy_document.json
}

data "aws_iam_policy_document" "cloudsaver_policy_base3_policy_document" {
  version = "2012-10-17"
  statement {
    sid    = "CloudSaverBase3"
    effect = "Allow"
    actions = [
      "rds:DescribeDBClusters",
      "rds:DescribeDBClusterSnapshots",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshots",
      "rds:DescribeReservedDBInstances",
      "rds:ListTagsForResource",
      "redshift:DescribeClusters",
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:ListTagsForResource",
      "s3:GetBucketLocation",
      "s3:GetBucketTagging",
      "s3:GetLifecycleConfiguration",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
      "sagemaker:DescribeDomain",
      "sagemaker:DescribeNotebookInstance",
      "sagemaker:DescribeProject",
      "sagemaker:ListDomains",
      "sagemaker:ListNotebookInstances",
      "sagemaker:ListProjects",
      "sagemaker:ListTags",
      "savingsplans:DescribeSavingsPlans",
      "securityhub:DescribeHub",
      "securityhub:ListTagsForResource",
      "sns:GetTopicAttributes",
      "sns:ListTagsForResource",
      "sns:ListTopics",
      "sqs:GetQueueAttributes",
      "sqs:ListQueues",
      "sqs:ListQueueTags",
      "ssm:DescribeDocument",
      "ssm:DescribeParameters",
      "ssm:DescribePatchBaselines",
      "ssm:GetParameters",
      "ssm:ListDocuments",
      "ssm:ListTagsForResource",
      "states:DescribeActivity",
      "states:DescribeStateMachine",
      "states:ListActivities",
      "states:ListStateMachines",
      "states:ListTagsForResource",
      "storagegateway:ListFileShares",
      "storagegateway:ListGateways",
      "storagegateway:ListTagsForResource",
      "storagegateway:ListVolumes",
      "support:DescribeTrustedAdvisorCheckRefreshStatuses",
      "support:DescribeTrustedAdvisorCheckResult",
      "support:DescribeTrustedAdvisorChecks",
      "support:DescribeTrustedAdvisorCheckSummaries",
      "transfer:DescribeConnector",
      "transfer:DescribeWorkflow",
      "transfer:ListConnectors",
      "transfer:ListTagsForResource",
      "transfer:ListWorkflows",
      "workspaces:DescribeTags",
      "workspaces:DescribeWorkspaceDirectories",
      "workspaces:DescribeWorkspaces"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "cloudsaver_role" {
  name               = "CloudSaver-Role"
  description        = "Role to be assumed by CloudSaver"
  assume_role_policy = data.aws_iam_policy_document.cs_assume_role.json
  managed_policy_arns = [
    aws_iam_policy.cloudsaver_policy_tagmanager.arn,
    aws_iam_policy.cloudsaver_policy_tagmanager2.arn,
    aws_iam_policy.cloudsaver_policy_base.arn,
    aws_iam_policy.cloudsaver_policy_base2.arn,
    aws_iam_policy.cloudsaver_policy_base3.arn
  ]
}

data "aws_iam_policy_document" "cs_assume_role" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::357040809576:root"]
    }
    actions = ["sts:AssumeRole"]
    condition {
      values   = [var.external_id]
      test     = "StringEquals"
      variable = "sts:AssumeRole"
    }
  }
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}


# PAYER ONLY

# StackSet
resource "aws_cloudformation_stack_set" "apiaccess" {
  count            = var.use_stackset && local.isMaster ? 1 : 0
  name             = var.stackset_name
  permission_model = "SERVICE_MANAGED"
  template_url     = "https://cover-cloudformation-templates.s3.ap-northeast-1.amazonaws.com/coverapiaccess-v1.yml"
  parameters = {
    Principal  = var.principal
    ExternalId = var.external_id
  }
  managed_execution {
    active = true
  }
  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }
  operation_preferences {
    max_concurrent_count    = 1
    failure_tolerance_count = 0
    region_concurrency_type = "SEQUENTIAL"
    region_order            = ["us-east-1"]
  }
}


# S3 bucket creation
resource "aws_s3_bucket" "s3_bucket_resource" {
  count  = local.isMaster ? 1 : 0
  bucket = var.cur_s3_bucket_name
}

# S3 bucket policy 
resource "aws_s3_bucket_policy" "s3_bucket_policy" {
  count      = local.isMaster ? 1 : 0
  bucket     = var.cur_s3_bucket_name
  depends_on = [aws_s3_bucket.s3_bucket_resource[0]]
  policy     = data.aws_iam_policy_document.s3_bucket_policy_document.json
}

# S3 bucket policy document
data "aws_iam_policy_document" "s3_bucket_policy_document" {
  version = "2012-10-17"
  statement {
    sid    = "Stmt1335892150622"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["billingreports.amazonaws.com"]
    }
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy"
    ]
    resources = [
      "${join("", ["arn:aws:s3:::", var.cur_s3_bucket_name])}"
    ]
  }
  statement {
    sid    = "Stmt1335892526596"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["billingreports.amazonaws.com"]
    }
    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${join("", ["arn:aws:s3:::", var.cur_s3_bucket_name, "/*"])}"
    ]
  }
}

# Cur report definition
resource "aws_cur_report_definition" "cur_report_def" {
  count                      = local.isMaster ? 1 : 0
  additional_schema_elements = ["RESOURCES"]
  compression                = "ZIP"
  format                     = "textORcsv"
  refresh_closed_reports     = true
  report_name                = var.cur_report_name
  report_versioning          = "OVERWRITE_REPORT"
  s3_bucket                  = aws_s3_bucket.s3_bucket_resource[0].bucket
  s3_prefix                  = var.cur_s3_prefix
  s3_region                  = var.cur_s3_bucket_region
  time_unit                  = "HOURLY"
}

# AcctAccessCurRole
resource "aws_iam_role" "AlphausAcctAccessCurRole" {
  count                = local.isMaster ? 1 : 0
  name                 = "AlphausAcctAccessCurRole"
  max_session_duration = 43200
  assume_role_policy   = data.aws_iam_policy_document.assume_role_policy.json
  inline_policy {
    name   = "root"
    policy = data.aws_iam_policy_document.root_cur.json
  }
  path = "/"
}
# AlphausAcctAccessCurRole policy document - assume role
data "aws_iam_policy_document" "assume_role_policy" {
  version = "2012-10-17"
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.principal]
    }
  }
}

# AlphausAcctAccessCurRole policy document - root
data "aws_iam_policy_document" "root_cur" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "s3:Get*",
      "s3:List*"
    ]
    resources = [
      "${aws_s3_bucket.s3_bucket_resource[0].arn}",
      "${aws_s3_bucket.s3_bucket_resource[0].arn}/*"
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "organizations:List*",
      "organizations:Describe*",
      "ec2:DescribeReservedInstances",
      "ec2:GetCapacityReservationUsage",
      "rds:DescribeReservedDBInstances",
      "elasticache:DescribeReservedCacheNodes",
      "es:DescribeReservedElasticsearchInstances",
      "redshift:DescribeReservedNodes",
      "savingsplans:DescribeSavingsPlan*",
      "cur:Describe*",
      "budgets:Describe*",
      "ce:Describe*",
      "ce:Get*",
      "ce:List*",
      "billingconductor:List*"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "iam:GetRole*",
      "iam:PutRolePolicy"
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/AlphausAcctAccessCurRole"]
  }
}
