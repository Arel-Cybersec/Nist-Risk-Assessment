# Create a simulated VPC for the FinTech Platform
resource "aws_vpc" "fintech_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

# Public Subnets for the load balancer tier, one per Availability Zone
# REMEDIATION NIST-06: Two AZs so losing one zone does not take the service down (CP-10)
resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"
}

# Explicit internet route so the public tier's reachability is defined in code
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

# REMEDIATION NIST-03: VPC Flow Logs for all accepted and rejected traffic (AU-12)
resource "aws_flow_log" "fintech_vpc" {
  vpc_id               = aws_vpc.fintech_vpc.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.audit.arn}/vpc-flow-logs/"

  depends_on = [aws_s3_bucket_policy.audit]
}

# REMEDIATION F-05: Hardened Security Group with restricted access
resource "aws_security_group" "secure_sg" {
  name        = "secure-api-sg"
  description = "Hardened security group for FinTech web instances"
  vpc_id      = aws_vpc.fintech_vpc.id

  # Fixed Rule: Only allowing SSH (Port 22) from a trusted corporate jump box/VPN IP
  ingress {
    description = "Allow SSH only from Trusted Corporate Network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.168.1.50/32"] # Mocked corporate office static IP address
  }

  # REMEDIATION NIST-02: Web traffic reaches instances only through the HTTPS load balancer
  ingress {
    description     = "Allow web traffic from the load balancer only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Outbound traffic rule
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# REMEDIATION NIST-06: Application tier as an Auto Scaling group across two AZs (CP-10)
resource "aws_launch_template" "app_server" {
  name_prefix            = "fintech-core-app-"
  image_id               = "ami-0c55b159cbfafe1f0"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  tag_specifications {
    resource_type = "instance"

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
  vpc_zone_identifier = [aws_subnet.public_subnet.id, aws_subnet.public_subnet_b.id]
  target_group_arns   = [aws_lb_target_group.app.arn]
  # Switch to "ELB" once the AMI serves the application, so failed HTTP checks replace instances
  health_check_type         = "EC2"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.app_server.id
    version = aws_launch_template.app_server.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }
}
