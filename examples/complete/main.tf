################################################################################
# Complete Example - Centralized Inspection VPC with Transit Gateway
#
# Architecture:
#   Spoke VPCs --> Transit Gateway --> Inspection VPC (Network Firewall) --> IGW
#
# This pattern routes all inter-VPC and egress traffic through a centralized
# inspection VPC where AWS Network Firewall performs deep packet inspection.
################################################################################

provider "aws" {
  region = "us-east-1"
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs                = slice(data.aws_availability_zones.available.names, 0, 2)
  inspection_vpc_cidr = "10.0.0.0/16"
  spoke_a_vpc_cidr    = "10.1.0.0/16"
  spoke_b_vpc_cidr    = "10.2.0.0/16"
}

################################################################################
# Inspection VPC
################################################################################

resource "aws_vpc" "inspection" {
  cidr_block           = local.inspection_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "inspection-vpc"
  }
}

# Firewall subnets - where Network Firewall endpoints are placed
resource "aws_subnet" "firewall" {
  count = length(local.azs)

  vpc_id            = aws_vpc.inspection.id
  cidr_block        = cidrsubnet(local.inspection_vpc_cidr, 12, count.index)
  availability_zone = local.azs[count.index]

  tags = {
    Name = "firewall-subnet-${local.azs[count.index]}"
  }
}

# TGW attachment subnets
resource "aws_subnet" "tgw_attachment" {
  count = length(local.azs)

  vpc_id            = aws_vpc.inspection.id
  cidr_block        = cidrsubnet(local.inspection_vpc_cidr, 12, count.index + 10)
  availability_zone = local.azs[count.index]

  tags = {
    Name = "tgw-attachment-subnet-${local.azs[count.index]}"
  }
}

# Public subnets for NAT/IGW
resource "aws_subnet" "public" {
  count = length(local.azs)

  vpc_id            = aws_vpc.inspection.id
  cidr_block        = cidrsubnet(local.inspection_vpc_cidr, 12, count.index + 20)
  availability_zone = local.azs[count.index]

  tags = {
    Name = "public-subnet-${local.azs[count.index]}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.inspection.id

  tags = {
    Name = "inspection-igw"
  }
}

# NAT Gateway (one per AZ for HA)
resource "aws_eip" "nat" {
  count  = length(local.azs)
  domain = "vpc"

  tags = {
    Name = "nat-eip-${local.azs[count.index]}"
  }
}

resource "aws_nat_gateway" "this" {
  count = length(local.azs)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "nat-gw-${local.azs[count.index]}"
  }

  depends_on = [aws_internet_gateway.this]
}

################################################################################
# Route Tables - Inspection VPC
################################################################################

# Public route table - routes to IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.inspection.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  # Return traffic to spokes goes through firewall endpoints
  dynamic "route" {
    for_each = [local.spoke_a_vpc_cidr, local.spoke_b_vpc_cidr]
    content {
      cidr_block      = route.value
      vpc_endpoint_id = module.network_firewall.endpoint_ids[local.azs[0]]
    }
  }

  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = length(local.azs)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Firewall subnet route table - routes to NAT/IGW
resource "aws_route_table" "firewall" {
  count  = length(local.azs)
  vpc_id = aws_vpc.inspection.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[count.index].id
  }

  tags = {
    Name = "firewall-rt-${local.azs[count.index]}"
  }
}

resource "aws_route_table_association" "firewall" {
  count = length(local.azs)

  subnet_id      = aws_subnet.firewall[count.index].id
  route_table_id = aws_route_table.firewall[count.index].id
}

# TGW attachment subnet route table - routes to firewall endpoints
resource "aws_route_table" "tgw" {
  count  = length(local.azs)
  vpc_id = aws_vpc.inspection.id

  route {
    cidr_block      = "0.0.0.0/0"
    vpc_endpoint_id = module.network_firewall.endpoint_ids[local.azs[count.index]]
  }

  tags = {
    Name = "tgw-rt-${local.azs[count.index]}"
  }
}

resource "aws_route_table_association" "tgw" {
  count = length(local.azs)

  subnet_id      = aws_subnet.tgw_attachment[count.index].id
  route_table_id = aws_route_table.tgw[count.index].id
}

################################################################################
# Transit Gateway
################################################################################

resource "aws_ec2_transit_gateway" "this" {
  description                     = "Central transit gateway for inspection pattern"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = {
    Name = "central-tgw"
  }
}

# Inspection VPC attachment
resource "aws_ec2_transit_gateway_vpc_attachment" "inspection" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  vpc_id             = aws_vpc.inspection.id
  subnet_ids         = aws_subnet.tgw_attachment[*].id

  appliance_mode_support = "enable"

  tags = {
    Name = "inspection-vpc-attachment"
  }
}

# TGW Route Tables
resource "aws_ec2_transit_gateway_route_table" "inspection" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id

  tags = {
    Name = "inspection-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table" "spoke" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id

  tags = {
    Name = "spoke-rt"
  }
}

# Associate inspection VPC with inspection route table
resource "aws_ec2_transit_gateway_route_table_association" "inspection" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspection.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

# Default route in spoke route table -> inspection VPC
resource "aws_ec2_transit_gateway_route" "spoke_default" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspection.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

################################################################################
# Spoke VPC A
################################################################################

resource "aws_vpc" "spoke_a" {
  cidr_block           = local.spoke_a_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "spoke-a-vpc"
  }
}

resource "aws_subnet" "spoke_a" {
  count = length(local.azs)

  vpc_id            = aws_vpc.spoke_a.id
  cidr_block        = cidrsubnet(local.spoke_a_vpc_cidr, 8, count.index)
  availability_zone = local.azs[count.index]

  tags = {
    Name = "spoke-a-subnet-${local.azs[count.index]}"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "spoke_a" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  vpc_id             = aws_vpc.spoke_a.id
  subnet_ids         = aws_subnet.spoke_a[*].id

  tags = {
    Name = "spoke-a-attachment"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "spoke_a" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke_a.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "spoke_a_to_inspection" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke_a.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

resource "aws_route_table" "spoke_a" {
  vpc_id = aws_vpc.spoke_a.id

  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = aws_ec2_transit_gateway.this.id
  }

  tags = {
    Name = "spoke-a-rt"
  }
}

resource "aws_route_table_association" "spoke_a" {
  count = length(local.azs)

  subnet_id      = aws_subnet.spoke_a[count.index].id
  route_table_id = aws_route_table.spoke_a.id
}

################################################################################
# Spoke VPC B
################################################################################

resource "aws_vpc" "spoke_b" {
  cidr_block           = local.spoke_b_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "spoke-b-vpc"
  }
}

resource "aws_subnet" "spoke_b" {
  count = length(local.azs)

  vpc_id            = aws_vpc.spoke_b.id
  cidr_block        = cidrsubnet(local.spoke_b_vpc_cidr, 8, count.index)
  availability_zone = local.azs[count.index]

  tags = {
    Name = "spoke-b-subnet-${local.azs[count.index]}"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "spoke_b" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  vpc_id             = aws_vpc.spoke_b.id
  subnet_ids         = aws_subnet.spoke_b[*].id

  tags = {
    Name = "spoke-b-attachment"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "spoke_b" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke_b.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "spoke_b_to_inspection" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke_b.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

resource "aws_route_table" "spoke_b" {
  vpc_id = aws_vpc.spoke_b.id

  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = aws_ec2_transit_gateway.this.id
  }

  tags = {
    Name = "spoke-b-rt"
  }
}

resource "aws_route_table_association" "spoke_b" {
  count = length(local.azs)

  subnet_id      = aws_subnet.spoke_b[count.index].id
  route_table_id = aws_route_table.spoke_b.id
}

################################################################################
# Network Firewall Module
################################################################################

module "network_firewall" {
  source = "../../"

  name   = "central-inspection-fw"
  vpc_id = aws_vpc.inspection.id

  subnet_ids = {
    for idx, subnet in aws_subnet.firewall :
    local.azs[idx] => subnet.id
  }

  firewall_policy_name = "centralized-inspection-policy"

  stateless_default_actions          = ["aws:forward_to_sfe"]
  stateless_fragment_default_actions = ["aws:drop"]

  stateless_rule_groups = [
    {
      name     = "block-high-risk-protocols"
      priority = 1
      capacity = 100
      rules = [
        {
          priority = 1
          actions  = ["aws:drop"]
          match_attributes = {
            protocols        = [6]
            source           = ["0.0.0.0/0"]
            destination      = ["0.0.0.0/0"]
            destination_port = ["23-23"] # Telnet
          }
        },
        {
          priority = 2
          actions  = ["aws:drop"]
          match_attributes = {
            protocols        = [6]
            source           = ["0.0.0.0/0"]
            destination      = ["0.0.0.0/0"]
            destination_port = ["3389-3389"] # RDP from external
          }
        }
      ]
    }
  ]

  stateful_rule_groups = [
    # Suricata IDS/IPS rules for deep packet inspection
    {
      name     = "enterprise-threat-detection"
      capacity = 500
      type     = "SURICATA"
      rules_string = <<-EOT
        # Block SSH brute force
        drop ssh any any -> $HOME_NET 22 (msg:"SSH brute force attempt"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; sid:2000001; rev:1;)

        # Detect port scanning
        alert tcp any any -> $HOME_NET any (msg:"Potential port scan detected"; flow:to_server; flags:S,12; threshold:type both, track by_src, count 20, seconds 10; sid:2000002; rev:1;)

        # Block known malware download patterns
        drop http any any -> any any (msg:"Blocked executable download"; flow:to_client,established; content:"Content-Type|3a| application/x-msdownload"; http_header; sid:2000003; rev:1;)

        # Block outbound to suspicious ports (common C2)
        drop tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555,6666,7777,8888,9999,1337] (msg:"Outbound C2 channel blocked"; flow:to_server; sid:2000004; rev:1;)

        # Detect DNS tunneling
        alert dns any any -> any any (msg:"Possible DNS tunneling - long query"; dns.query; content:"."; offset:50; sid:2000005; rev:1;)

        # Block TOR exit nodes
        drop tls any any -> any any (msg:"TOR connection blocked"; tls.sni; content:".onion"; endswith; sid:2000006; rev:1;)

        # Alert on lateral movement attempts
        alert tcp $HOME_NET any -> $HOME_NET [135,139,445,3389,5985,5986] (msg:"Potential lateral movement"; flow:to_server; sid:2000007; rev:1;)
      EOT
      rule_variables = {
        HOME_NET     = ["10.0.0.0/8"]
        EXTERNAL_NET = ["0.0.0.0/0"]
      }
    },

    # Block known malicious domains
    {
      name     = "malicious-domain-blocklist"
      capacity = 200
      type     = "DOMAIN_LIST"
      domain_list = [
        ".malware-domain.com",
        ".phishing-campaign.net",
        ".crypto-mining-pool.io",
        ".command-and-control.xyz",
        ".data-exfiltration.org",
        ".ransomware-payment.com"
      ]
    }
  ]

  enable_logging       = true
  log_destination_type = "s3"
  log_types            = ["ALERT", "FLOW"]

  deletion_protection = true
  encryption_type     = "AWS_OWNED_KMS_KEY"

  tags = {
    Environment  = "production"
    Example      = "complete"
    SecurityTier = "critical"
    Pattern      = "centralized-inspection"
  }
}

################################################################################
# Outputs
################################################################################

output "firewall_id" {
  description = "Network Firewall ID"
  value       = module.network_firewall.firewall_id
}

output "firewall_arn" {
  description = "Network Firewall ARN"
  value       = module.network_firewall.firewall_arn
}

output "firewall_endpoints" {
  description = "Firewall endpoint IDs per AZ"
  value       = module.network_firewall.endpoint_ids
}

output "transit_gateway_id" {
  description = "Transit Gateway ID"
  value       = aws_ec2_transit_gateway.this.id
}

output "inspection_vpc_id" {
  description = "Inspection VPC ID"
  value       = aws_vpc.inspection.id
}

output "spoke_a_vpc_id" {
  description = "Spoke A VPC ID"
  value       = aws_vpc.spoke_a.id
}

output "spoke_b_vpc_id" {
  description = "Spoke B VPC ID"
  value       = aws_vpc.spoke_b.id
}
