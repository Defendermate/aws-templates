/**
 * Defendermate cross-account read-only IAM role.
 *
 * Creates:
 *   - aws.iam.Role               (trust policy: DM platform account +
 *                                 External ID + aws:PrincipalArn pattern)
 *   - aws.iam.Policy             (read-only inventory + describe)
 *   - aws.iam.Policy             (reachability — SSM + ECS Exec)
 *   - aws.iam.RolePolicyAttachment (one per policy)
 *
 * Policies are inlined (matching ../../connector/pulumi/index.ts convention)
 * so this file is self-contained for `pulumi up` from any local copy. The
 * canonical permission list lives in ../../connector/readOnlyPolicy.json and
 * reachabilityPolicy.json — keep in sync when updating either.
 */
import * as aws from "@pulumi/aws";

// --- inputs ---
const roleName = "DefendermateRole";
const externalId = "<paste the value from the wizard>"; // change me — paste the External ID from the wizard
// Environment-specific: dev / staging / prod each have a different Defendermate
// AWS account. Read the value from the wizard's "Defendermate Account ID" panel
// for the tenant you're connecting.
const defenderMateAccountId = "<see Defendermate Account ID in the wizard>"; // change me
const principalArnPattern = "role/dm-core-*";
const iamPath = "/";

// --- policy documents ---
const readOnlyPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "Identity",
      Effect: "Allow",
      Action: ["sts:GetCallerIdentity"],
      Resource: "*",
    },
    {
      Sid: "EC2Network",
      Effect: "Allow",
      Action: [
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
        "ec2:DescribeNatGateways",
      ],
      Resource: "*",
    },
    {
      Sid: "IAMRead",
      Effect: "Allow",
      Action: [
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
        "iam:GetPolicyVersion",
      ],
      Resource: "*",
    },
    {
      Sid: "Lambda",
      Effect: "Allow",
      Action: ["lambda:ListFunctions", "lambda:GetPolicy"],
      Resource: "*",
    },
    {
      Sid: "EKS",
      Effect: "Allow",
      Action: ["eks:ListClusters", "eks:DescribeCluster"],
      Resource: "*",
    },
    {
      Sid: "ELBv2",
      Effect: "Allow",
      Action: [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
      ],
      Resource: "*",
    },
    {
      Sid: "S3",
      Effect: "Allow",
      Action: [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPolicy",
      ],
      Resource: "*",
    },
    {
      Sid: "RDS",
      Effect: "Allow",
      Action: ["rds:DescribeDBInstances"],
      Resource: "*",
    },
    {
      Sid: "SecretsManager",
      Effect: "Allow",
      Action: [
        "secretsmanager:ListSecrets",
        "secretsmanager:GetResourcePolicy",
      ],
      Resource: "*",
    },
    {
      Sid: "KMS",
      Effect: "Allow",
      Action: [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy",
      ],
      Resource: "*",
    },
    {
      Sid: "Inspector2",
      Effect: "Allow",
      Action: ["inspector2:ListFindings"],
      Resource: "*",
    },
    {
      Sid: "AutoScaling",
      Effect: "Allow",
      Action: ["autoscaling:DescribeAutoScalingGroups"],
      Resource: "*",
    },
    {
      Sid: "ECS",
      Effect: "Allow",
      Action: [
        "ecs:ListClusters",
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
      ],
      Resource: "*",
    },
    {
      Sid: "ECR",
      Effect: "Allow",
      Action: ["ecr:BatchGetImage"],
      Resource: "*",
    },
    {
      Sid: "Organizations",
      Effect: "Allow",
      Action: [
        "organizations:DescribeOrganization",
        "organizations:ListParents",
        "organizations:ListPolicies",
        "organizations:ListTargetsForPolicy",
        "organizations:DescribePolicy",
      ],
      Resource: "*",
    },
    {
      Sid: "DmStreamsWafv2Ingestion",
      Effect: "Allow",
      Action: [
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL",
      ],
      Resource: "*",
    },
    {
      Sid: "GuardDuty",
      Effect: "Allow",
      Action: [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListCoverage",
      ],
      Resource: "*",
    },
  ],
};

const reachabilityPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "SSMExecution",
      Effect: "Allow",
      Action: [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:TerminateSession",
      ],
      Resource: "*",
    },
    {
      Sid: "ECSExec",
      Effect: "Allow",
      Action: ["ecs:ExecuteCommand"],
      Resource: "*",
    },
  ],
};

// --- trust policy ---
const trustPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Principal: {
        AWS: `arn:aws:iam::${defenderMateAccountId}:root`,
      },
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: {
          "sts:ExternalId": externalId,
        },
        StringLike: {
          "aws:PrincipalArn": `arn:aws:iam::${defenderMateAccountId}:${principalArnPattern}`,
        },
      },
    },
  ],
};

// --- resources ---
const connector = new aws.iam.Role("connector", {
  name: roleName,
  path: iamPath,
  assumeRolePolicy: JSON.stringify(trustPolicy),
  // Matches the dm-streams runtime AssumeRole duration; without this,
  // customers with org-wide reduced defaults would hit ValidationError
  // at scan time.
  maxSessionDuration: 3600,
  tags: {
    Service: "defendermate.com",
    Support: "support@defendermate.com",
  },
});

const readOnly = new aws.iam.Policy("read-only", {
  name: `${roleName}-read-only`,
  path: iamPath,
  description: "Read-only inventory + describe permissions for Defendermate.",
  policy: JSON.stringify(readOnlyPolicy),
});

const reachability = new aws.iam.Policy("reachability", {
  name: `${roleName}-reachability`,
  path: iamPath,
  description: "Permissions required for reachability checks (SSM + ECS Exec).",
  policy: JSON.stringify(reachabilityPolicy),
});

new aws.iam.RolePolicyAttachment("read-only-attach", {
  role: connector.name,
  policyArn: readOnly.arn,
});

new aws.iam.RolePolicyAttachment("reachability-attach", {
  role: connector.name,
  policyArn: reachability.arn,
});

export const roleArn = connector.arn;
export const readOnlyPolicyArn = readOnly.arn;
export const reachabilityPolicyArn = reachability.arn;
