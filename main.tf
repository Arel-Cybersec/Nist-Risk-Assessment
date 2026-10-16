# Simulated VPC for the FinTech Platform
resource "aws_vpc" "fintech_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "fintech-vpc" }
}

# Lock down the default security group so nothing can fall back onto it
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.fintech_vpc.id
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.fintech_vpc.id
}

# Public Subnet for our API/Web Tier (no automatic public IPs)
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.fintech_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.fintech_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public.id
}

# REMEDIATION F-05: No management ports at all. Admin access is via SSM Session Manager.
# Only HTTPS is exposed; plaintext HTTP is removed.
resource "aws_security_group" "secure_sg" {
  name        = "secure-api-sg"
  description = "Hardened security group for FinTech web instances"
  vpc_id      = aws_vpc.fintech_vpc.id

  ingress {
    description = "Public HTTPS for the web application"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS out for SSM, package updates and AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# REMEDIATION F-06: Hardened application instance
resource "aws_instance" "app_server" {
  ami                    = var.app_ami_id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.data.arn
    volume_type = "gp3"
  }

  tags = {
    Name        = "FinTech-Core-App"
    Environment = "Production"
  }
}

# Incident response (F-10, Playbook B): an empty security group, ready before it is needed,
# that cuts a compromised instance off from all traffic in one command.
resource "aws_security_group" "isolation" {
  #checkov:skip=CKV2_AWS_5:Attached only during an incident (governance/incident-response.md, Playbook B)
  name        = "isolation-sg"
  description = "Incident response: no inbound or outbound traffic"
  vpc_id      = aws_vpc.fintech_vpc.id
}

# Stable public address for HTTPS clients and outbound SSM/AWS API traffic.
# Production would front this with a load balancer and keep the instance private.
resource "aws_eip" "app" {
  domain     = "vpc"
  instance   = aws_instance.app_server.id
  depends_on = [aws_internet_gateway.igw]
}
