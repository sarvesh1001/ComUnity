# outputs.tf - Output values for auth service infrastructure

output "app_server_public_ip" {
  description = "Public IP address of the application server"
  value       = aws_instance.app_server.public_ip
}

output "app_server_elastic_ip" {
  description = "Elastic IP address of the application server"
  value       = aws_eip.app_ip.public_ip
}

output "database_endpoint" {
  description = "Endpoint address of the RDS database"
  value       = aws_db_instance.auth_db.endpoint
}

output "database_username" {
  description = "Database admin username"
  value       = aws_db_instance.auth_db.username
}

output "database_name" {
  description = "Name of the initial database"
  value       = aws_db_instance.auth_db.db_name
}

output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app_sg.id
}

output "ssh_command" {
  description = "Command to SSH into the app server"
  value       = "ssh -i '${var.key_pair_name}.pem' ubuntu@${aws_eip.app_ip.public_ip}"
}

# scripts/terraform/outputs.tf
output "db_secret_arn" {
  description = "ARN of the database secret"
  value       = aws_secretsmanager_secret.db_secret.arn
}

output "aadhaar_param_name" {
  description = "Name of the Aadhaar API key parameter"
  value       = aws_ssm_parameter.aadhaar_api_key.name
}
output "redis_endpoint" {
  description = "Redis primary endpoint"
  value       = module.redis.primary_endpoint
}

output "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = module.opensearch.domain_endpoint
}