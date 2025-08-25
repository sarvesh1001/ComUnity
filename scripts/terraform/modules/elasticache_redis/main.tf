resource "aws_elasticache_subnet_group" "redis" {
  name       = "${var.name_prefix}-redis-subnet-group"
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "redis_sg" {
  name        = "${var.name_prefix}-redis-sg"
  description = "Security group for Redis cluster"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = var.port
    to_port         = var.port
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-redis-sg"
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${var.name_prefix}-redis"
  replication_group_description = "Redis cluster for ${var.name_prefix}"
  node_type                     = var.node_type
  port                          = var.port
  parameter_group_name          = var.parameter_group_name
  automatic_failover_enabled    = var.automatic_failover

  # Cluster mode settings
  num_node_groups         = var.cluster_mode_enabled ? var.num_node_groups : null
  replicas_per_node_group = var.cluster_mode_enabled ? var.replicas_per_node_group : null

  # Non-cluster mode settings
  number_cache_clusters = var.cluster_mode_enabled ? null : var.number_cache_clusters

  engine_version         = var.engine_version
  at_rest_encryption_enabled   = true
  transit_encryption_enabled   = var.transit_encryption
  kms_key_id             = var.kms_key_arn

  subnet_group_name  = aws_elasticache_subnet_group.redis.name
  security_group_ids = [aws_security_group.redis_sg.id]

  tags = {
    Name = "${var.name_prefix}-redis"
  }
}