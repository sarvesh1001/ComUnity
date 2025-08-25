  # CloudWatch Alarms for Production Monitoring

  # SNS Topic for Alert Notifications
  resource "aws_sns_topic" "production_alerts" {
    name = "auth-service-production-alerts"
  }

  # Email Subscription
  resource "aws_sns_topic_subscription" "email_alerts" {
    topic_arn = aws_sns_topic.production_alerts.arn
    protocol  = "email"
    endpoint  = var.alert_email
  }

  # --------------------------
  # EC2 INSTANCE ALARMS
  # --------------------------
  resource "aws_cloudwatch_metric_alarm" "ec2_cpu_high" {
    alarm_name          = "auth-ec2-cpu-utilization-high"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "5"
    metric_name         = "CPUUtilization"
    namespace           = "AWS/EC2"
    period              = "60"
    statistic           = "Average"
    threshold           = "80"
    alarm_description   = "EC2 CPU utilization > 80% for 5 minutes"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      InstanceId = aws_instance.app_server.id
    }
    tags = {
      Service = "AuthService"
    }
  }

  resource "aws_cloudwatch_metric_alarm" "ec2_status_check" {
    alarm_name          = "auth-ec2-status-check-failed"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "2"
    metric_name         = "StatusCheckFailed"
    namespace           = "AWS/EC2"
    period              = "60"
    statistic           = "Maximum"
    threshold           = "0"
    alarm_description   = "EC2 instance status check failed"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      InstanceId = aws_instance.app_server.id
    }
  }

  # --------------------------
  # RDS DATABASE ALARMS
  # --------------------------
  resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
    alarm_name          = "auth-rds-cpu-utilization-high"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "5"
    metric_name         = "CPUUtilization"
    namespace           = "AWS/RDS"
    period              = "60"
    statistic           = "Average"
    threshold           = "75"
    alarm_description   = "RDS CPU utilization > 75% for 5 minutes"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      DBInstanceIdentifier = aws_db_instance.auth_db.identifier
    }
  }

  resource "aws_cloudwatch_metric_alarm" "rds_free_storage_low" {
    alarm_name          = "auth-rds-free-storage-low"
    comparison_operator = "LessThanThreshold"
    evaluation_periods  = "3"
    metric_name         = "FreeStorageSpace"
    namespace           = "AWS/RDS"
    period              = "300"  # 5 minutes
    statistic           = "Average"
    threshold           = tostring(aws_db_instance.auth_db.allocated_storage * 1024 * 1024 * 1024 * 0.2)  # 20% of storage
    alarm_description   = "RDS free storage < 20% of allocated storage"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      DBInstanceIdentifier = aws_db_instance.auth_db.identifier
    }
  }

  resource "aws_cloudwatch_metric_alarm" "rds_connections_high" {
    alarm_name          = "auth-rds-connections-high"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "3"
    metric_name         = "DatabaseConnections"
    namespace           = "AWS/RDS"
    period              = "60"
    statistic           = "Average"
    threshold           = "100"
    alarm_description   = "RDS connection count > 100 for 3 minutes"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      DBInstanceIdentifier = aws_db_instance.auth_db.identifier
    }
  }

  # --------------------------
  # APPLICATION ALARMS (CUSTOM METRICS)
  # --------------------------
  resource "aws_cloudwatch_metric_alarm" "app_5xx_errors" {
    alarm_name          = "auth-app-5xx-errors-high"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "2"
    metric_name         = "5XXError"
    namespace           = "AuthService"
    period              = "60"
    statistic           = "Sum"
    threshold           = "10"  # 10 errors per minute
    alarm_description   = "Application 5XX errors > 10 per minute"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    tags = {
      Service = "AuthService"
    }
  }

  resource "aws_cloudwatch_metric_alarm" "app_high_latency" {
    alarm_name          = "auth-app-high-latency"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "3"
    metric_name         = "Latency"
    namespace           = "AuthService"
    period              = "60"
    statistic           = "Average"
    threshold           = "1000"  # 1000 ms
    alarm_description   = "Application average latency > 1000ms"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    tags = {
      Service = "AuthService"
    }
  }

  # --------------------------
  # SECRETS MANAGER ALARMS
  # --------------------------
  resource "aws_cloudwatch_metric_alarm" "secrets_manager_errors" {
    alarm_name          = "auth-secrets-manager-errors"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "1"
    metric_name         = "Errors"
    namespace           = "AWS/SecretsManager"
    period              = "60"
    statistic           = "Sum"
    threshold           = "0"
    alarm_description   = "Errors accessing Secrets Manager"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      SecretId = aws_secretsmanager_secret.db_secret.name
    }
  }

  # --------------------------
  # KMS ALARMS
  # --------------------------
  resource "aws_cloudwatch_metric_alarm" "kms_throttles" {
    alarm_name          = "auth-kms-throttles"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods  = "3"
    metric_name         = "ThrottledRequests"
    namespace           = "AWS/KMS"
    period              = "60"
    statistic           = "Sum"
    threshold           = "0"
    alarm_description   = "KMS throttling detected"
    alarm_actions       = [aws_sns_topic.production_alerts.arn]
    dimensions = {
      KeyId = aws_kms_key.auth.key_id
    }
  }

  # Required for account ID
  data "aws_caller_identity" "current" {}