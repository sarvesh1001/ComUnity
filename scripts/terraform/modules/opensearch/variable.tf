variable "domain_name" {
  description = "Name of the OpenSearch domain"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for OpenSearch"
  type        = list(string)
}

variable "allowed_security_groups" {
  description = "Security Group IDs allowed to access OpenSearch"
  type        = list(string)
}

variable "elasticsearch_version" {
  description = "OpenSearch version"
  type        = string
  default     = "OpenSearch_2.5"
}

variable "instance_type" {
  description = "Instance type for data nodes"
  type        = string
  default     = "t3.small.search"
}

variable "instance_count" {
  description = "Number of data nodes"
  type        = number
  default     = 1
}

variable "dedicated_master_enabled" {
  description = "Enable dedicated master nodes"
  type        = bool
  default     = false
}

variable "dedicated_master_type" {
  description = "Instance type for dedicated master nodes"
  type        = string
  default     = "t3.small.search"
}

variable "dedicated_master_count" {
  description = "Number of dedicated master nodes"
  type        = number
  default     = 3
}

variable "zone_awareness_enabled" {
  description = "Enable zone awareness"
  type        = bool
  default     = false
}

variable "availability_zone_count" {
  description = "Number of availability zones"
  type        = number
  default     = 2
}

variable "ebs_volume_size" {
  description = "EBS volume size in GB"
  type        = number
  default     = 10
}

variable "ebs_volume_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp2"
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
}

variable "cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN"
  type        = string
  default     = null
}

variable "enable_slow_logs" {
  description = "Enable slow logs"
  type        = bool
  default     = false
}