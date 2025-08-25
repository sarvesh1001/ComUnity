# AWS Configuration
aws_region       = "ap-south-1"
key_pair_name    = "auth-service-prod-key"  # Name of your existing AWS key pair

# Network Configuration
vpc_cidr         = "10.0.0.0/16"
public_subnet_cidr = "10.0.1.0/24"
availability_zone = "ap-south-1a"

# Database Configuration (PRODUCTION VALUES)
db_username     = "auth_admin"      # Production DB username
db_password     = "StrongP@ssw0rd!23"  # Production DB password (rotate regularly!)
db_name         = "auth_production" # Production database name

# Instance Configuration
instance_type    = "t3.medium"      # Larger instance for production
db_instance_class = "db.t4g.medium" # Larger DB instance for production

# scripts/terraform/terraform.tfvars
aadhaar_api_key = "your-actual-api-key-here"
alert_email = "your-team@example.com"  # Replace with actual email