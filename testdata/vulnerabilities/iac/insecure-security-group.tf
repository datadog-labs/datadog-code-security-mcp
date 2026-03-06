# Terraform configuration with insecure security group rules
# This file demonstrates common network misconfigurations for E2E testing

# VULNERABLE: Security group with unrestricted SSH access
resource "aws_security_group" "open_ssh" {
  name        = "allow_ssh_from_anywhere"
  description = "Allow SSH from anywhere"
  vpc_id      = "vpc-12345678"

  # VULNERABLE: SSH open to the world (0.0.0.0/0)
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
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
    Name = "allow-ssh-open"
  }
}

# VULNERABLE: Security group with unrestricted RDP access
resource "aws_security_group" "open_rdp" {
  name        = "allow_rdp_from_anywhere"
  description = "Allow RDP from anywhere"
  vpc_id      = "vpc-12345678"

  # VULNERABLE: RDP open to the world
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow-rdp-open"
  }
}

# VULNERABLE: Security group allowing all traffic
resource "aws_security_group" "allow_all" {
  name        = "allow_all_traffic"
  description = "Allow all inbound traffic"
  vpc_id      = "vpc-12345678"

  # VULNERABLE: All ports open to the world
  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABLE: All ports open via IPv6
  ingress {
    description      = "All traffic IPv6"
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "allow-all"
  }
}

# VULNERABLE: Database port exposed publicly
resource "aws_security_group" "open_database" {
  name        = "allow_database"
  description = "Database access"
  vpc_id      = "vpc-12345678"

  # VULNERABLE: MySQL port open to the world
  ingress {
    description = "MySQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABLE: PostgreSQL port open to the world
  ingress {
    description = "PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "open-database"
  }
}
