output "domain_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = aws_elasticsearch_domain.opensearch.endpoint
}

output "security_group_id" {
  description = "OpenSearch security group ID"
  value       = aws_security_group.opensearch_sg.id
}

output "domain_arn" {
  description = "OpenSearch domain ARN"
  value       = aws_elasticsearch_domain.opensearch.arn
}