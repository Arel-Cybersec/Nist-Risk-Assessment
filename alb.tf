# REMEDIATION NIST-02: HTTPS-only public entry point (SC-8, SC-13)
# TLS terminates at the load balancer; port 80 exists only to redirect to 443.

resource "aws_security_group" "alb_sg" {
  name        = "public-alb-sg"
  description = "Public HTTPS entry point for the FinTech web tier"
  vpc_id      = aws_vpc.fintech_vpc.id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from the internet, redirected to HTTPS by the listener"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Forward to application instances inside the VPC only"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.fintech_vpc.cidr_block]
  }
}

resource "aws_acm_certificate" "app" {
  domain_name       = var.app_domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Waits until the DNS records from the acm_validation_records output exist and the certificate is issued
resource "aws_acm_certificate_validation" "app" {
  certificate_arn = aws_acm_certificate.app.arn
}

resource "aws_lb" "app" {
  name                       = "fintech-app-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb_sg.id]
  subnets                    = [aws_subnet.public_subnet.id, aws_subnet.public_subnet_b.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name     = "fintech-app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.fintech_vpc.id

  health_check {
    path    = "/"
    matcher = "200-399"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.app.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
