# F-04: No CloudTrail and no VPC flow logs.
# F-05: SSH open to the internet; web traffic over plaintext HTTP.
# F-06: IMDSv1 allowed and an unencrypted root volume.
resource "aws_vpc" "fintech_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.fintech_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_security_group" "open_sg" {
  name        = "open-api-sg"
  description = "Default-open security group"
  vpc_id      = aws_vpc.fintech_vpc.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.open_sg.id]

  metadata_options {
    http_tokens = "optional"
  }

  root_block_device {
    encrypted = false
  }

  tags = {
    Name        = "FinTech-Core-App"
    Environment = "Production"
  }
}
