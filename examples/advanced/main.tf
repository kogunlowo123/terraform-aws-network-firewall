################################################################################
# Advanced Network Firewall Example
# Full firewall with Suricata rules and domain filtering
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
    Name = "advanced-firewall-vpc"
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

  name   = "advanced-firewall"
  vpc_id = aws_vpc.this.id

  subnet_ids = {
    for idx, subnet in aws_subnet.firewall :
    data.aws_availability_zones.available.names[idx] => subnet.id
  }

  firewall_policy_name = "advanced-security-policy"

  stateless_default_actions          = ["aws:forward_to_sfe"]
  stateless_fragment_default_actions = ["aws:drop"]

  # Stateless rules for L3/L4 filtering
  stateless_rule_groups = [
    {
      name     = "block-known-bad-ports"
      priority = 1
      capacity = 100
      rules = [
        {
          priority = 1
          actions  = ["aws:drop"]
          match_attributes = {
            protocols        = [6] # TCP
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
            destination_port = ["3389-3389"] # RDP
          }
        },
        {
          priority = 5
          actions  = ["aws:drop"]
          match_attributes = {
            protocols        = [6]
            source           = ["0.0.0.0/0"]
            destination      = ["0.0.0.0/0"]
            destination_port = ["445-445"] # SMB
          }
        }
      ]
    }
  ]

  # Stateful rule groups
  stateful_rule_groups = [
    # Suricata IDS/IPS rules
    {
      name     = "suricata-threat-detection"
      capacity = 200
      type     = "SURICATA"
      rules_string = <<-EOT
        # Block SSH brute force attempts
        drop ssh any any -> $HOME_NET 22 (msg:"Potential SSH brute force"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)

        # Alert on known malicious user agents
        alert http any any -> any any (msg:"Suspicious User-Agent detected"; flow:to_server,established; content:"Mozilla/4.0"; http_user_agent; sid:1000002; rev:1;)

        # Block outbound connections to known C2 ports
        drop tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555,6666,7777,8888,9999] (msg:"Potential C2 communication on suspicious port"; flow:to_server; sid:1000003; rev:1;)

        # Alert on DNS queries for TXT records (potential data exfiltration)
        alert dns any any -> any any (msg:"DNS TXT query - potential data exfil"; dns.query; content:"."; dns_query; sid:1000004; rev:1;)

        # Block cryptocurrency mining pools
        drop tls any any -> any any (msg:"Blocked cryptocurrency mining pool"; tls.sni; content:"pool."; nocase; sid:1000005; rev:1;)
      EOT
      rule_variables = {
        HOME_NET    = ["10.0.0.0/16"]
        EXTERNAL_NET = ["0.0.0.0/0"]
      }
    },

    # Domain filtering
    {
      name     = "block-malicious-domains"
      capacity = 100
      type     = "DOMAIN_LIST"
      domain_list = [
        ".malware-domain.com",
        ".phishing-site.net",
        ".crypto-miner.io",
        ".bad-actor.org",
        ".command-control.xyz"
      ]
    }
  ]

  enable_logging       = true
  log_destination_type = "cloudwatch"
  log_types            = ["ALERT", "FLOW"]

  deletion_protection = false

  tags = {
    Environment = "staging"
    Example     = "advanced"
    SecurityTier = "high"
  }
}

################################################################################
# Outputs
################################################################################

output "firewall_id" {
  value = module.network_firewall.firewall_id
}

output "firewall_arn" {
  value = module.network_firewall.firewall_arn
}

output "policy_arn" {
  value = module.network_firewall.policy_arn
}

output "endpoint_ids" {
  value = module.network_firewall.endpoint_ids
}
