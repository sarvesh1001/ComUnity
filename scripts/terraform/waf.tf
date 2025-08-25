# AWS WAF v2 Configuration for Auth Service
# Designed for 100M+ users with enterprise security

# Main WAF Web ACL
resource "aws_wafv2_web_acl" "auth_service_waf" {
  name        = "auth-service-waf-${var.environment}"
  description = "WAF for ComUnity Auth Service - ${var.environment}"
  scope       = "CLOUDFRONT" # Use REGIONAL for ALB

  default_action {
    allow {}
  }

  # Rate limiting rule - Critical for 100M users
  rule {
    name     = "RateLimitRule"
    priority = 1

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
        
        scope_down_statement {
          byte_match_statement {
            search_string = "/auth/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "STARTS_WITH"
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "rate_limit_exceeded"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # Geographic blocking rule
  rule {
    name     = "GeoBlockRule"
    priority = 2

    override_action {
      none {}
    }

    statement {
      geo_match_statement {
        country_codes = var.blocked_countries
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "geo_blocked"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GeoBlockRule"
      sampled_requests_enabled   = true
    }
  }

  # IP reputation rule
  rule {
    name     = "IPReputationRule"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "ip_reputation_blocked"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPReputationRule"
      sampled_requests_enabled   = true
    }
  }

  # Known bad inputs rule
  rule {
    name     = "KnownBadInputsRule"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"

        # Exclude rules that might interfere with legitimate auth requests
        excluded_rule {
          name = "Host_localhost_HEADER"
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 400
          custom_response_body_key = "bad_input_blocked"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRule"
      sampled_requests_enabled   = true
    }
  }

  # SQL injection rule
  rule {
    name     = "SQLInjectionRule"
    priority = 5

    override_action {
      none {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "sql_injection_blocked"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLInjectionRule"
      sampled_requests_enabled   = true
    }
  }

  # XSS rule
  rule {
    name     = "XSSRule"
    priority = 6

    override_action {
      none {}
    }

    statement {
      xss_match_statement {
        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "xss_blocked"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "XSSRule"
      sampled_requests_enabled   = true
    }
  }

  # Large request body rule (prevent DoS)
  rule {
    name     = "LargeRequestBodyRule"
    priority = 7

    override_action {
      none {}
    }

    statement {
      size_constraint_statement {
        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }
        comparison_operator = "GT"
        size                = 8192 # 8KB limit
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 413
          custom_response_body_key = "request_too_large"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "LargeRequestBodyRule"
      sampled_requests_enabled   = true
    }
  }

  # API abuse detection (high frequency patterns)
  rule {
    name     = "APIAbuseRule"
    priority = 8

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = 300 # 300 requests per 5 minutes per IP
        aggregate_key_type = "IP"
        
        scope_down_statement {
          or_statement {
            statement {
              byte_match_statement {
                search_string = "/auth/login"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
                positional_constraint = "EXACTLY"
              }
            }
            statement {
              byte_match_statement {
                search_string = "/otp/send"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
                positional_constraint = "EXACTLY"
              }
            }
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "api_abuse_detected"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "APIAbuseRule"
      sampled_requests_enabled   = true
    }
  }

  # Bot control rule
  rule {
    name     = "BotControlRule"
    priority = 9

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"

        managed_rule_group_configs {
          aws_managed_rules_bot_control_rule_set {
            inspection_level = "TARGETED"
          }
        }
      }
    }

    action {
      count {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BotControlRule"
      sampled_requests_enabled   = true
    }
  }

  # Allow health checks
  rule {
    name     = "AllowHealthChecks"
    priority = 10

    override_action {
      none {}
    }

    statement {
      byte_match_statement {
        search_string = "/health"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "STARTS_WITH"
      }
    }

    action {
      allow {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowHealthChecks"
      sampled_requests_enabled   = true
    }
  }

  # Custom response bodies
  custom_response_body {
    key          = "rate_limit_exceeded"
    content      = jsonencode({
      error   = "rate_limit_exceeded"
      message = "Too many requests. Please try again later."
      retry_after = 300
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "geo_blocked"
    content      = jsonencode({
      error   = "geo_blocked"
      message = "Access from your location is not permitted."
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "ip_reputation_blocked"
    content      = jsonencode({
      error   = "ip_reputation_blocked"
      message = "Access denied due to IP reputation."
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "bad_input_blocked"
    content      = jsonencode({
      error   = "bad_input_blocked"
      message = "Invalid input detected."
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "sql_injection_blocked"
    content      = jsonencode({
      error   = "sql_injection_blocked"
      message = "Malicious request blocked."
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "xss_blocked"
    content      = jsonencode({
      error   = "xss_blocked"
      message = "Malicious request blocked."
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "request_too_large"
    content      = jsonencode({
      error   = "request_too_large"
      message = "Request body too large."
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "api_abuse_detected"
    content      = jsonencode({
      error   = "api_abuse_detected"
      message = "API abuse detected. Access temporarily restricted."
      retry_after = 300
    })
    content_type = "APPLICATION_JSON"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AuthServiceWAF"
    sampled_requests_enabled   = true
  }

  tags = merge(var.common_tags, {
    Name        = "auth-service-waf-${var.environment}"
    Environment = var.environment
    Service     = "auth-service"
  })
}

# IP Set for trusted IPs (internal services, monitoring)
resource "aws_wafv2_ip_set" "trusted_ips" {
  name           = "auth-service-trusted-ips-${var.environment}"
  description    = "Trusted IP addresses for auth service"
  scope          = "CLOUDFRONT"
  ip_address_version = "IPV4"

  addresses = var.trusted_ip_addresses

  tags = merge(var.common_tags, {
    Name        = "auth-service-trusted-ips-${var.environment}"
    Environment = var.environment
  })
}

# Allow rule for trusted IPs
resource "aws_wafv2_web_acl" "auth_service_waf_with_trusted_ips" {
  name        = "auth-service-waf-complete-${var.environment}"
  description = "Complete WAF for ComUnity Auth Service with trusted IPs"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Trusted IPs bypass all rules
  rule {
    name     = "AllowTrustedIPs"
    priority = 0

    override_action {
      none {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.trusted_ips.arn
      }
    }

    action {
      allow {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowTrustedIPs"
      sampled_requests_enabled   = true
    }
  }

  # Include all rules from the main WAF (priorities 1-10)
  dynamic "rule" {
    for_each = aws_wafv2_web_acl.auth_service_waf.rule
    content {
      name     = rule.value.name
      priority = rule.value.priority + 1 # Shift priorities

      override_action {
        none {}
      }

      statement = rule.value.statement

      action = rule.value.action

      visibility_config = rule.value.visibility_config
    }
  }

  # Include custom response bodies
  dynamic "custom_response_body" {
    for_each = aws_wafv2_web_acl.auth_service_waf.custom_response_body
    content {
      key          = custom_response_body.value.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AuthServiceWAFComplete"
    sampled_requests_enabled   = true
  }

  tags = merge(var.common_tags, {
    Name        = "auth-service-waf-complete-${var.environment}"
    Environment = var.environment
    Service     = "auth-service"
  })
}

# CloudWatch Log Group for WAF logs
resource "aws_cloudwatch_log_group" "waf_log_group" {
  name              = "/aws/wafv2/auth-service-${var.environment}"
  retention_in_days = var.waf_log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_id

  tags = merge(var.common_tags, {
    Name        = "auth-service-waf-logs-${var.environment}"
    Environment = var.environment
  })
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "waf_logging" {
  resource_arn            = aws_wafv2_web_acl.auth_service_waf_with_trusted_ips.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_log_group.arn]

  # Redact sensitive information from logs
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  redacted_fields {
    body {}
  }

  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "COUNT"
        }
      }
      requirement = "MEETS_ANY"
    }
  }
}

# CloudWatch Alarms for WAF
resource "aws_cloudwatch_metric_alarm" "high_blocked_requests" {
  alarm_name          = "auth-service-waf-high-blocked-requests-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.blocked_requests_threshold
  alarm_description   = "High number of blocked requests detected"
  alarm_actions       = [var.sns_alert_topic_arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.auth_service_waf_with_trusted_ips.name
    Region = data.aws_region.current.name
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rate_limit_triggered" {
  alarm_name          = "auth-service-waf-rate-limit-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RateLimitRule"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "Rate limiting rule frequently triggered"
  alarm_actions       = [var.sns_alert_topic_arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.auth_service_waf_with_trusted_ips.name
    Region = data.aws_region.current.name
    Rule   = "RateLimitRule"
  }

  tags = var.common_tags
}

# Output values
output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.auth_service_waf_with_trusted_ips.arn
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.auth_service_waf_with_trusted_ips.id
}

output "waf_log_group_name" {
  description = "Name of the WAF log group"
  value       = aws_cloudwatch_log_group.waf_log_group.name
}

# Variables (add to variables.tf)
variable "environment" {
  description = "Environment name"
  type        = string
}

variable "rate_limit_per_5min" {
  description = "Rate limit per 5 minutes per IP"
  type        = number
  default     = 2000
}

variable "blocked_countries" {
  description = "List of country codes to block"
  type        = list(string)
  default     = []
}

variable "trusted_ip_addresses" {
  description = "List of trusted IP addresses"
  type        = list(string)
  default     = []
}

variable "blocked_requests_threshold" {
  description = "Threshold for blocked requests alarm"
  type        = number
  default     = 1000
}

variable "waf_log_retention_days" {
  description = "WAF log retention in days"
  type        = number
  default     = 90
}

variable "cloudwatch_kms_key_id" {
  description = "KMS key ID for CloudWatch encryption"
  type        = string
  default     = null
}

variable "sns_alert_topic_arn" {
  description = "SNS topic ARN for alerts"
  type        = string
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# Data sources
data "aws_region" "current" {}
