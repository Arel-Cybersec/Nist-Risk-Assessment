# Create a simulated VPC for the FinTech Platform
resource "aws_vpc" "fintech_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

# Public Subnet for our API/Web Tier
resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
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

  # Fixed Rule: Standard web traffic allowed, but ready for HTTPS transition
  ingress {
    description = "Allow production web traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Open for public web application access only
  }

  # Outbound traffic rule
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Application Instance attached to the secure network profile
resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet.id
  
  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  tags = {
    Name        = "FinTech-Core-App"
    Environment = "Production"
  }
}