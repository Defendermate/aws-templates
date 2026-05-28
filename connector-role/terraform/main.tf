###############################################################################
# Defendermate cross-account read-only IAM role.
#
# Creates:
#   - aws_iam_role          (trust policy: DM platform account + External ID
#                            + aws:PrincipalArn pattern)
#   - aws_iam_policy        (read-only inventory + describe)
#   - aws_iam_policy        (reachability — SSM + ECS Exec)
#   - aws_iam_role_policy_attachment (one per policy)
#
# Policies are inlined (matching ../../connector/terraform/main.tf convention)
# so this file is self-contained for `terraform apply` from any local copy.
# The canonical permission list lives in ../../connector/readOnlyPolicy.json
# and reachabilityPolicy.json — keep in sync when updating either.
###############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "role_name" {
  type        = string
  description = "Name of the IAM role to create."
  default     = "DefendermateRole"
}

variable "external_id" {
  type        = string
  description = "External ID from the Defendermate wizard. Required."
  # External IDs are not access-key-grade secrets; they're a per-connection
  # token the trust policy requires for confused-deputy prevention. Marking
  # sensitive = false matches how the wizard displays it (plain text).
  sensitive = false
}

variable "defendermate_account_id" {
  type        = string
  description = "Defendermate's own AWS account ID. Environment-specific — see the wizard's 'Defendermate Account ID' display (dev / staging / prod differ). No default; pass via -var or .tfvars."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.defendermate_account_id))
    error_message = "defendermate_account_id must be a 12-digit AWS account ID."
  }
}

variable "principal_arn_pattern" {
  type        = string
  description = "Pattern matched against aws:PrincipalArn — restricts which DM-side IAM principals can AssumeRole."
  default     = "role/dm-core-*"
}

variable "path" {
  type        = string
  description = "IAM path for the role and policies."
  default     = "/"
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "trust" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.defendermate_account_id}:root"]
    }

    actions = ["sts:AssumeRole"]

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:${data.aws_partition.current.partition}:iam::${var.defendermate_account_id}:${var.principal_arn_pattern}"]
    }
  }
}

resource "aws_iam_role" "connector" {
  name               = var.role_name
  path               = var.path
  assume_role_policy = data.aws_iam_policy_document.trust.json
  # Matches the dm-streams runtime AssumeRole duration; without this,
  # customers with org-wide reduced defaults would hit ValidationError
  # at scan time.
  max_session_duration = 3600

  tags = {
    Service = "defendermate.com"
    Support = "support@defendermate.com"
  }
}

resource "aws_iam_policy" "read_only" {
  name        = "${var.role_name}-read-only"
  path        = var.path
  description = "Read-only inventory + describe permissions for Defendermate."
  policy      = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "Identity",
          "Effect": "Allow",
          "Action": [
            "sts:GetCallerIdentity"
          ],
          "Resource": "*"
        },
        {
          "Sid": "EC2Network",
          "Effect": "Allow",
          "Action": [
            "ec2:DescribeRegions",
            "ec2:DescribeInstances",
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeRouteTables",
            "ec2:DescribeNetworkAcls",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeAddresses",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeInternetGateways",
            "ec2:DescribeNatGateways"
          ],
          "Resource": "*"
        },
        {
          "Sid": "IAMRead",
          "Effect": "Allow",
          "Action": [
            "iam:ListUsers",
            "iam:ListRoles",
            "iam:ListGroups",
            "iam:ListInstanceProfiles",
            "iam:ListMFADevices",
            "iam:ListAccessKeys",
            "iam:ListAttachedUserPolicies",
            "iam:ListAttachedRolePolicies",
            "iam:ListAttachedGroupPolicies",
            "iam:ListUserPolicies",
            "iam:ListRolePolicies",
            "iam:ListGroupPolicies",
            "iam:ListGroupsForUser",
            "iam:GetUser",
            "iam:GetRole",
            "iam:GetGroup",
            "iam:GetUserPolicy",
            "iam:GetRolePolicy",
            "iam:GetGroupPolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion"
          ],
          "Resource": "*"
        },
        {
          "Sid": "Lambda",
          "Effect": "Allow",
          "Action": [
            "lambda:ListFunctions",
            "lambda:GetPolicy"
          ],
          "Resource": "*"
        },
        {
          "Sid": "EKS",
          "Effect": "Allow",
          "Action": [
            "eks:ListClusters",
            "eks:DescribeCluster"
          ],
          "Resource": "*"
        },
        {
          "Sid": "ELBv2",
          "Effect": "Allow",
          "Action": [
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeListeners",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth"
          ],
          "Resource": "*"
        },
        {
          "Sid": "S3",
          "Effect": "Allow",
          "Action": [
            "s3:ListAllMyBuckets",
            "s3:GetBucketLocation",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetEncryptionConfiguration",
            "s3:GetBucketPolicy"
          ],
          "Resource": "*"
        },
        {
          "Sid": "RDS",
          "Effect": "Allow",
          "Action": [
            "rds:DescribeDBInstances"
          ],
          "Resource": "*"
        },
        {
          "Sid": "SecretsManager",
          "Effect": "Allow",
          "Action": [
            "secretsmanager:ListSecrets",
            "secretsmanager:GetResourcePolicy"
          ],
          "Resource": "*"
        },
        {
          "Sid": "KMS",
          "Effect": "Allow",
          "Action": [
            "kms:ListKeys",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
            "kms:GetKeyPolicy"
          ],
          "Resource": "*"
        },
        {
          "Sid": "Inspector2",
          "Effect": "Allow",
          "Action": [
            "inspector2:ListFindings"
          ],
          "Resource": "*"
        },
        {
          "Sid": "AutoScaling",
          "Effect": "Allow",
          "Action": [
            "autoscaling:DescribeAutoScalingGroups"
          ],
          "Resource": "*"
        },
        {
          "Sid": "ECS",
          "Effect": "Allow",
          "Action": [
            "ecs:ListClusters",
            "ecs:ListTasks",
            "ecs:DescribeTasks",
            "ecs:DescribeTaskDefinition"
          ],
          "Resource": "*"
        },
        {
          "Sid": "ECR",
          "Effect": "Allow",
          "Action": [
            "ecr:BatchGetImage"
          ],
          "Resource": "*"
        },
        {
          "Sid": "Organizations",
          "Effect": "Allow",
          "Action": [
            "organizations:DescribeOrganization",
            "organizations:ListParents",
            "organizations:ListPolicies",
            "organizations:ListTargetsForPolicy",
            "organizations:DescribePolicy"
          ],
          "Resource": "*"
        },
        {
          "Sid": "DmStreamsWafv2Ingestion",
          "Effect": "Allow",
          "Action": [
            "wafv2:ListWebACLs",
            "wafv2:GetWebACL",
            "wafv2:ListResourcesForWebACL"
          ],
          "Resource": "*"
        },
        {
          "Sid": "GuardDuty",
          "Effect": "Allow",
          "Action": [
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "guardduty:ListCoverage"
          ],
          "Resource": "*"
        }
      ]
    }
  EOT
}

resource "aws_iam_policy" "reachability" {
  name        = "${var.role_name}-reachability"
  path        = var.path
  description = "Permissions required for reachability checks (SSM + ECS Exec)."
  policy      = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "SSMExecution",
          "Effect": "Allow",
          "Action": [
            "ssm:SendCommand",
            "ssm:GetCommandInvocation",
            "ssm:TerminateSession"
          ],
          "Resource": "*"
        },
        {
          "Sid": "ECSExec",
          "Effect": "Allow",
          "Action": [
            "ecs:ExecuteCommand"
          ],
          "Resource": "*"
        }
      ]
    }
  EOT
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.connector.name
  policy_arn = aws_iam_policy.read_only.arn
}

resource "aws_iam_role_policy_attachment" "reachability" {
  role       = aws_iam_role.connector.name
  policy_arn = aws_iam_policy.reachability.arn
}

output "role_name" {
  value = aws_iam_role.connector.name
}

output "role_arn" {
  value = aws_iam_role.connector.arn
}

output "read_only_policy_arn" {
  value = aws_iam_policy.read_only.arn
}

output "reachability_policy_arn" {
  value = aws_iam_policy.reachability.arn
}
