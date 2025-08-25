# main.tf - Starter Infrastructure for Nextdoor-like App
provider "aws" {
  region = var.aws_region
}

# Create VPC with public subnet
resource "aws_vpc" "main" {
    cidr_block = var.vpc_cidr
  tags = {
    Name = "AuthServiceVPC"
}
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
    cidr_block        = var.public_subnet_cidr
    availability_zone = var.availability_zone
    tags = {
    Name = "PublicSubnet"
  }
}

# Internet Gateway for public access
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "MainIGW"
  }
}

# Route table for public subnet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "PublicRouteTable"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group for application access
resource "aws_security_group" "app_sg" {
  name        = "app-security-group"
  description = "Allow SSH and HTTP access"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["103.134.116.198/32"]
  }
  ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
 }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "AppSecurityGroup"
  }
}

# Ubuntu 22.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = [var.ubuntu_ami_owner]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# EC2 instance for application server
resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  key_name               = var.key_pair_name
  iam_instance_profile = aws_iam_instance_profile.app_profile.name  # Add this line

  tags = {
    Name = "AuthService-AppServer"
  }

  user_data = <<-EOF
              #!/bin/bash
              sudo apt update -y
              sudo apt install -y docker.io
              sudo systemctl start docker
              sudo systemctl enable docker
              sudo usermod -aG docker ubuntu
              EOF
}

# Output the public IP for SSH access
output "app_server_public_ip" {
  value = aws_instance.app_server.public_ip
}

# RDS for PostgreSQL (we'll use this temporarily)
resource "aws_db_instance" "auth_db" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "15"
  instance_class       = var.db_instance_class
  db_name              = var.db_name
  username             = var.db_username
  password             = var.db_password
  skip_final_snapshot  = true
  publicly_accessible  = false  # For development only
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  db_subnet_group_name = aws_db_subnet_group.main.name

  tags = {
    Name = "AuthService-DB"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "main-subnet-group"
  subnet_ids = [aws_subnet.public.id]

  tags = {
    Name = "DBSubnetGroup"
  }
}

# Elastic IP for static IP address
resource "aws_eip" "app_ip" {
  instance = aws_instance.app_server.id
  tags = {
    Name = "AppServer-EIP"
  }
}
# Create private subnet for data services
resource "aws_subnet" "data_private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = var.availability_zone
  tags = {
    Name = "DataPrivateSubnet"
  }
}

# Create Redis cluster
module "redis" {
  source = "./modules/elasticache_redis"

  name_prefix            = "auth-service"
  vpc_id                = aws_vpc.main.id
  subnet_ids            = [aws_subnet.data_private.id]
  allowed_security_groups = [aws_security_group.app_sg.id]
  kms_key_arn           = aws_kms_key.auth.arn
  node_type             = "cache.t4g.micro"
  engine_version        = "7.0"
  automatic_failover    = true
  transit_encryption    = true
}

# Create OpenSearch cluster
module "opensearch" {
  source = "./modules/opensearch"

  domain_name           = "auth-service"
  vpc_id                = aws_vpc.main.id
  subnet_ids            = [aws_subnet.data_private.id]
  allowed_security_groups = [aws_security_group.app_sg.id]
  kms_key_arn           = aws_kms_key.auth.arn
  instance_type         = "t3.small.search"
  instance_count        = 1
}