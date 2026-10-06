# REMEDIATION NIST-19: Customer-managed keys for regulated data (SC-12, SC-28(1), PT-2)
#
# Separation of duties: the account root principal administers the keys but cannot
# use them, and only named workload roles can encrypt or decrypt, and only through S3.
# PHI has its own key. The break-glass role can decrypt PII but not PHI.

locals {
  s3_via_primary = "s3.${var.aws_region}.amazonaws.com"
  s3_via_replica = "s3.${var.replica_region}.amazonaws.com"

  macie_service_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"

  key_admin_actions = [
    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
    "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
    "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
  ]

  # Roles that read regulated objects for replication, backup and scanning
  data_service_role_arns = [
    aws_iam_role.s3_replication.arn,
    aws_iam_role.backup.arn,
    aws_iam_role.malware_protection.arn,
  ]
}

data "aws_iam_policy_document" "pii_key" {
  #checkov:skip=CKV_AWS_111:Key policy; Resource "*" means this key only
  #checkov:skip=CKV_AWS_356:Key policy; Resource "*" means this key only
  statement {
    sid       = "KeyAdministrationOnly"
    actions   = local.key_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "DecryptThroughS3"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = concat(
        [aws_iam_role.fintech_core_app.arn, aws_iam_role.pii_breakglass_read.arn],
        local.data_service_role_arns
      )
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_via_primary]
    }
  }

  statement {
    sid       = "MalwareScanValidationObject"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.malware_protection.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_via_primary]
    }
  }

  statement {
    sid       = "MacieClassification"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.macie_service_role_arn]
    }
  }
}

data "aws_iam_policy_document" "phi_key" {
  #checkov:skip=CKV_AWS_111:Key policy; Resource "*" means this key only
  #checkov:skip=CKV_AWS_356:Key policy; Resource "*" means this key only
  statement {
    sid       = "KeyAdministrationOnly"
    actions   = local.key_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "DecryptThroughS3"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = concat([aws_iam_role.fintech_core_app.arn], local.data_service_role_arns)
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_via_primary]
    }
  }

  statement {
    sid       = "MacieClassification"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.macie_service_role_arn]
    }
  }
}

resource "aws_kms_key" "pii" {
  description             = "Default encryption for the PII bucket"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.pii_key.json
}

resource "aws_kms_alias" "pii" {
  name          = "alias/fintech-pii"
  target_key_id = aws_kms_key.pii.key_id
}

resource "aws_kms_key" "phi" {
  description             = "Required encryption for objects under phi/ in the PII bucket"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.phi_key.json
}

resource "aws_kms_alias" "phi" {
  name          = "alias/fintech-phi"
  target_key_id = aws_kms_key.phi.key_id
}

# ── Replica-region keys: only the replication role may encrypt with them ──

data "aws_iam_policy_document" "replica_key" {
  #checkov:skip=CKV_AWS_111:Key policy; Resource "*" means this key only
  #checkov:skip=CKV_AWS_356:Key policy; Resource "*" means this key only
  statement {
    sid       = "KeyAdministrationOnly"
    actions   = local.key_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "ReplicationEncrypt"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.s3_replication.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_via_replica]
    }
  }
}

resource "aws_kms_key" "replica_pii" {
  provider                = aws.replica
  description             = "Encryption for replicated PII objects"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.replica_key.json
}

resource "aws_kms_key" "replica_phi" {
  provider                = aws.replica
  description             = "Encryption for replicated PHI objects"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.replica_key.json
}
