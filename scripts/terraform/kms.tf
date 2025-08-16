# KMS key resource (example; adjust as per your setup)
resource "aws_kms_key" "auth" {
  description             = "Auth Service KMS Key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# Allow the auth-service role to use KMS for core operations
data "aws_iam_policy_document" "kms_auth" {
  statement {
    sid     = "AllowAuthServiceKMSBasic"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GetPublicKey",
      "kms:Sign",
      "kms:DescribeKey",
      "kms:GetKeyRotationStatus",
    ]
    resources = [aws_kms_key.auth.arn]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.auth_service.arn]
    }

    # Optional: enforce encryption context usage
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "kms:EncryptionContextKeys"
      values   = ["service", "env"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:service"
      values   = ["auth"]
    }
  }
}

resource "aws_kms_key_policy" "auth" {
  key_id = aws_kms_key.auth.key_id
  policy = data.aws_iam_policy_document.kms_auth.json
}
