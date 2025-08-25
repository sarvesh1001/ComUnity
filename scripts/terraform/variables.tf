# variables.tf - Input variables for auth service infrastructure

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "key_pair_name" {
  description = "Name of the EC2 key pair for SSH access"
  type        = string
  default     = "your-key-pair-name"
}

variable "db_password" {
  description = "Password for the database admin user"
  type        = string
  sensitive   = true
  default     = "temp-password-123" # Override in production!
}

variable "db_username" {
  description = "Username for the database admin user"
  type        = string
  default     = "admin"
}

variable "db_name" {
  description = "Name of the initial database"
  type        = string
  default     = "authdb"
}

variable "instance_type" {
  description = "EC2 instance type for app server"
  type        = string
  default     = "t3.micro"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

variable "ubuntu_ami_owner" {
  description = "Canonical owner ID for Ubuntu AMIs"
  type        = string
  default     = "099720109477"
}

variable "availability_zone" {
  description = "Availability zone for resources"
  type        = string
  default     = "ap-south-1a"
}

variable "aadhaar_api_key" {
  description = "API key for Aadhaar verification service"
  type        = string
  sensitive   = true
  default     = "dummy-key-for-dev" # Override in terraform.tfvars
} 
variable "alert_email" {
  description = "Email address for receiving alerts"
  type        = string
  default     = "devops@example.com"
}