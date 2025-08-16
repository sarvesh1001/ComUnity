# scripts/terraform/secrets.tf
resource "aws_secretsmanager_secret" "db_secret" {
  name        = "prod/auth-service/database"
  description = "Database credentials for auth service"
}

resource "aws_secretsmanager_secret_version" "db_secret_version" {
  secret_id = aws_secretsmanager_secret.db_secret.id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.auth_db.endpoint
    dbname   = var.db_name
  })
}

resource "aws_ssm_parameter" "aadhaar_api_key" {
  name        = "/auth-service/aadhaar-api-key"
  description = "API key for Aadhaar verification service"
  type        = "SecureString"
  value       = var.aadhaar_api_key
}