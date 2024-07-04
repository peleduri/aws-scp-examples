# The AWS Organizations service has a hard limit of five SCPs per account.
# This is why we consolidate multiple SCPs into a single SCP.

resource "aws_organizations_policy" "scp-security-package" {
  description = "Common Service Control Policies (SCPs) Package"
  name        = "tf-scp-security-package"
  content     = data.aws_iam_policy_document.scp-security-package.json
}

data "aws_iam_policy_document" "scp-security-package" {
  statement {
    effect = "Deny"
    actions = [
      "organizations:LeaveOrganization",  # Prevent member accounts from leaving the organization
      "iam:DeleteAccountPasswordPolicy",  # Prevent Modification of IAM Password Policy with an Exception for an Administrator Role
      "iam:UpdateAccountPasswordPolicy",  # Prevent Modification of IAM Password Policy with an Exception for an Administrator Role
      "iam:CreateUser", # Prevent Creation of New IAM Users or Access Keys
      "iam:CreateAccessKey",  # Prevent Creation of New IAM Users or Access Keys
      "access-analyzer:DeleteAnalyzer", # Prevent Users from Disabling AWS Access Analyzer in an account
      "aws-marketplace:Subscribe",  # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-marketplace:Unsubscribe",  # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-marketplace:CreatePrivateMarketplace",   # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-marketplace:CreatePrivateMarketplaceRequests", # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-marketplace:AssociateProductsWithPrivateMarketplace",   # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-marketplace:DisassociateProductsFromPrivateMarketplace", # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-marketplace:UpdatePrivateMarketplaceSettings", # Restrict AWS Marketplace Product Subscription Changes to a Privileged Role
      "aws-portal:ModifyAccount", # Prevent Users from Modifying Account and Billing Settings
      "aws-portal:ModifyBilling",   # Prevent Users from Modifying Account and Billing Settings
      "aws-portal:ModifyPaymentMethods",  # Prevent Users from Modifying Account and Billing Settings
      "backup:DeleteBackupPlan",  # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:DeleteBackupSelection", # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:DeleteBackupVault", # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:DeleteBackupVaultAccessPolicy", # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:DeleteBackupVaultNotifications",  # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:DeleteRecoveryPoint", # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:PutBackupVaultAccessPolicy",  # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:PutBackupVaultNotifications", # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:UpdateBackupPlan",  # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:UpdateRecoveryPointLifecycle",  # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "backup:UpdateRegionSettings",    # Prevent Users from Deleting and Changing AWS Backup Policies and Vaults
      "cloudtrail:StopLogging",       # Prevent Users from Disabling AWS CloudTrail
      "cloudtrail:DeleteTrail",       # Prevent Users from Disabling AWS CloudTrail
      "ec2:CreateDefaultSubnet",      # Prevent Users from Creating Default VPC and Subnet
      "ec2:CreateDefaultVpc",          # Prevent Users from Creating Default VPC and Subnet
      "kms:ScheduleKeyDeletion",  # Prevent Users from Deleting KMS Keys
      "kms:Delete*", # Prevent Users from Deleting KMS Keys
      "account:EnableRegion", # Restrict Region Enable/Disable Actions to a Privileged Role
      "account:DisableRegion", # Restrict Region Enable/Disable Actions to a Privileged Role
      "config:DeleteConfigRule", # Prevent Users from Disabling AWS Config
      "ec2:DeleteNatGateway", # Protect NAT Gateway Deletion
      "ec2:DeleteInternetGateway", # Protect Internet Gateway Deletion
      "ec2:DisableEbsEncryptionByDefault" # Prevent Users from Disabling EBS Default Encryption
    ]
    resources = ["*"]
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values = [
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess_*",
        "arn:aws:iam::*:role/TFC_AWS_APPLY_ROLE",
      ]
    }
  }
}

resource "aws_organizations_policy_attachment" "scp-security-package" {
  for_each = toset([
    local.account_id_dev,
    local.account_id_prod,
    local.account_id_sandbox,
  ])
  policy_id = aws_organizations_policy.scp-security-package.id
  target_id = each.value
}
