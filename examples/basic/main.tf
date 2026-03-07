################################################################################
# Basic Network Firewall Example
# Deploys a firewall with simple stateless rules
################################################################################

provider "aws" {
  region = "us-east-1"
}

data "aws_availability_zones" "available" {
  state = "available"
}

################################################################################
# VPC for Firewall
################################################################################

resource "aws_vpc" "this" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "basic-firewall-vpc"
  }
}

resource "aws_subnet" "firewall" {
  count = 2

  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet("10.0.0.0/16", 12, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "firewall-subnet-${data.aws_availability_zones.available.names[count.index]}"
  }
}

################################################################################
# Network Firewall Module
################################################################################

module "network_firewall" {
  source = "../../"

  name   = "basic-firewall"
  vpc_id = aws_vpc.this.id

  subnet_ids = {
    for idx, subnet in aws_subnet.firewall :
    data.aws_availability_zones.available.names[idx] => subnet.id
  }

  stateless_default_actions          = ["aws:forward_to_sfe"]
  stateless_fragment_default_actions = ["aws:forward_to_sfe"]

  stateless_rule_groups = [
    {
      name     = "drop-icmp"
      priority = 1
      capacity = 100
      rules = [
        {
          priority = 1
          actions  = ["aws:drop"]
          match_attributes = {
            protocols   = [1] # ICMP
            source      = ["0.0.0.0/0"]
            destination = ["0.0.0.0/0"]
          }
        }
      ]
    },
    {
      name     = "allow-https"
      priority = 10
      capacity = 100
      rules = [
        {
          priority = 1
          actions  = ["aws:pass"]
          match_attributes = {
            protocols        = [6] # TCP
            source           = ["10.0.0.0/16"]
            destination      = ["0.0.0.0/0"]
            destination_port = ["443-443"]
          }
        }
      ]
    }
  ]

  enable_logging       = true
  log_destination_type = "cloudwatch"
  log_types            = ["ALERT", "FLOW"]

  tags = {
    Environment = "dev"
    Example     = "basic"
  }
}

################################################################################
# Outputs
################################################################################

output "firewall_arn" {
  value = module.network_firewall.firewall_arn
}

output "endpoint_ids" {
  value = module.network_firewall.endpoint_ids
}
