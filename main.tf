# Create a simulated VPC for the FinTech Platform
resource "aws_vpc" "fintech_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

# REMEDIATION NIST-16: Explicit tiers (PL-8, SC-7)
#   public  subnets: load balancer only, routed to the internet gateway
#   private subnets: application instances, no internet route at all;
#                    AWS APIs are reached through VPC endpoints
# Two Availability Zones per tier (NIST-06, CP-10)

resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Tier = "public" }
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = { Tier = "public" }
}

resource "aws_subnet" "private_app_a" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Tier = "private-app" }
}

resource "aws_subnet" "private_app_b" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.12.0/24"
  availability_zone = "${var.aws_region}b"

  tags = { Tier = "private-app" }
}

# The VPC's default security group allows nothing, so resources cannot fall back to it
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.fintech_vpc.id
}

resource "aws_internet_gateway" "fintech_igw" {
  vpc_id = aws_vpc.fintech_vpc.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.fintech_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fintech_igw.id
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_subnet_b.id
  route_table_id = aws_route_table.public.id
}

# No default route: the application tier cannot reach the internet
resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.fintech_vpc.id
}

resource "aws_route_table_association" "private_app_a" {
  subnet_id      = aws_subnet.private_app_a.id
  route_table_id = aws_route_table.private_app.id
}

resource "aws_route_table_association" "private_app_b" {
  subnet_id      = aws_subnet.private_app_b.id
  route_table_id = aws_route_table.private_app.id
}

# ── VPC endpoints (private path to AWS APIs) ──

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.fintech_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_app.id]
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "vpc-endpoints-sg"
  description = "HTTPS from inside the VPC to interface endpoints"
  vpc_id      = aws_vpc.fintech_vpc.id

  ingress {
    description = "HTTPS from the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.fintech_vpc.cidr_block]
  }
}

# SSM Session Manager (replaces SSH), KMS for session encryption, CloudWatch Logs for transcripts
resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["ssm", "ssmmessages", "ec2messages", "kms", "logs"])

  vpc_id              = aws_vpc.fintech_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

# REMEDIATION NIST-03: VPC Flow Logs for all accepted and rejected traffic (AU-12)
resource "aws_flow_log" "fintech_vpc" {
  vpc_id               = aws_vpc.fintech_vpc.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.audit.arn}/vpc-flow-logs/"

  depends_on = [aws_s3_bucket_policy.audit]
}

# REMEDIATION F-05, NIST-10, NIST-24: Application security group
# - no SSH: administration goes through SSM Session Manager (logged)
# - web traffic only from the load balancer
# - deny-by-default egress: HTTPS to the S3 gateway endpoint and the interface endpoints only
resource "aws_security_group" "secure_sg" {
  name        = "secure-api-sg"
  description = "Hardened security group for FinTech web instances"
  vpc_id      = aws_vpc.fintech_vpc.id

  ingress {
    description     = "Allow web traffic from the load balancer only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description     = "HTTPS to S3 through the gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }

  egress {
    description     = "HTTPS to SSM, KMS and CloudWatch Logs interface endpoints"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }
}

# REMEDIATION NIST-20: Encrypt every new EBS volume in the region (SC-28)
resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

# REMEDIATION NIST-11: AMI resolved from Amazon's own published images, not a pasted ID (CM-2, SR-4)
data "aws_ami" "al2023" {
  count       = var.ami_id == null ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  app_ami_id = var.ami_id != null ? var.ami_id : data.aws_ami.al2023[0].id
}

# REMEDIATION NIST-06, NIST-09, NIST-11, NIST-20: Hardened launch template
resource "aws_launch_template" "app_server" {
  name_prefix            = "fintech-core-app-"
  image_id               = local.app_ami_id
  instance_type          = "t3.micro"
  ebs_optimized          = true
  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  iam_instance_profile {
    arn = aws_iam_instance_profile.fintech_core_app.arn
  }

  # IMDSv2 only, one network hop: SSRF cannot read instance credentials (SC-7, CM-7)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_type           = "gp3"
      volume_size           = 30
      encrypted             = true
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name        = "FinTech-Core-App"
      Environment = "Production"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name        = "FinTech-Core-App"
      Environment = "Production"
    }
  }
}

resource "aws_autoscaling_group" "app_server" {
  name                = "fintech-core-app"
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2
  vpc_zone_identifier = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id]
  target_group_arns   = [aws_lb_target_group.app.arn]
  # Switch to "ELB" once the AMI serves the application, so failed HTTP checks replace instances
  health_check_type         = "EC2"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.app_server.id
    version = aws_launch_template.app_server.latest_version
  }

  tag {
    key                 = "Name"
    value               = "FinTech-Core-App"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }
}
