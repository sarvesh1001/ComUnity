# IAM Role for EC2
resource "aws_iam_role" "app_role" {
  name = "AuthServiceAppRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Existing policy attachments
resource "aws_iam_role_policy_attachment" "secrets_manager" {
  role       = aws_iam_role.app_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"
}

# New policy for KMS usage
resource "aws_iam_policy" "kms_access" {
  name        = "AuthServiceKMSAccess"
  description = "Allow AuthService to use specific KMS key"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKMSCoreOps",
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GetPublicKey",
          "kms:Sign",
          "kms:DescribeKey",
          "kms:GetKeyRotationStatus"
        ],
        Resource = aws_kms_key.auth.arn
      }
    ]
  })
}

# Attach KMS policy to the role
resource "aws_iam_role_policy_attachment" "kms_access_attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.kms_access.arn
}

# Instance profile for EC2 launch
resource "aws_iam_instance_profile" "app_profile" {
  name = "AuthServiceInstanceProfile"
  role = aws_iam_role.app_role.name
}
# Add CloudWatch permissions to the IAM role
resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.app_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}