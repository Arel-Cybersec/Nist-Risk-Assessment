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

# ── Subnets ──────────────────────────────────────────────────────────
# Public subnets hold only the load balancer (two AZs, as ALBs require). The application
# instance lives in a private subnet with no route to the internet (F-13).
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.fintech_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.fintech_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "private_app" {
  vpc_id                  = aws_vpc.fintech_vpc.id
  cidr_block              = "10.0.10.0/24"
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

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# No default route: the private subnet reaches AWS only through VPC endpoints
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.fintech_vpc.id
}

resource "aws_route_table_association" "private_app" {
  subnet_id      = aws_subnet.private_app.id
  route_table_id = aws_route_table.private.id
}

# ── VPC endpoints: SSM and S3 without internet access ────────────────
resource "aws_security_group" "endpoints" {
  name        = "vpc-endpoints-sg"
  description = "Interface endpoints for SSM, reachable only from the app instance"
  vpc_id      = aws_vpc.fintech_vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_app" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from the application instance"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.secure_sg.id
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = toset(["ssm", "ssmmessages", "ec2messages"])
  vpc_id              = aws_vpc.fintech_vpc.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private_app.id]
  security_group_ids  = [aws_security_group.endpoints.id]
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.fintech_vpc.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# REMEDIATION F-05 / F-13: No management ports and no direct internet exposure. The instance
# accepts HTTPS only from the load balancer; admin access is via SSM Session Manager.
resource "aws_security_group" "secure_sg" {
  name        = "secure-api-sg"
  description = "Hardened security group for FinTech web instances"
  vpc_id      = aws_vpc.fintech_vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.secure_sg.id
  description                  = "HTTPS from the load balancer only"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_endpoints" {
  security_group_id            = aws_security_group.secure_sg.id
  description                  = "HTTPS to the SSM interface endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_s3" {
  security_group_id = aws_security_group.secure_sg.id
  description       = "HTTPS to S3 through the gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
}

# REMEDIATION F-06: Hardened application instance
resource "aws_instance" "app_server" {
  ami                         = var.app_ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_app.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.secure_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  monitoring                  = true
  ebs_optimized               = true

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
