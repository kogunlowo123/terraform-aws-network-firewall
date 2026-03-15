terraform {
  required_version = ">= 1.7.0"
}

module "test" {
  source = "../"

  name   = "test-network-firewall"
  vpc_id = "vpc-0a1b2c3d4e5f60001"
  subnet_ids = {
    "us-east-1a" = "subnet-0123456789abcdef0"
    "us-east-1b" = "subnet-0123456789abcdef1"
  }

  stateless_default_actions          = ["aws:forward_to_sfe"]
  stateless_fragment_default_actions = ["aws:forward_to_sfe"]

  stateful_rule_groups = [
    {
      name         = "block-domains"
      capacity     = 100
      type         = "DOMAIN_LIST"
      domain_list  = [".example.com", ".malware.test"]
    }
  ]

  enable_logging       = true
  log_destination_type = "cloudwatch"
  log_types            = ["ALERT", "FLOW"]

  tags = {
    Environment = "test"
    Module      = "terraform-aws-network-firewall"
  }
}
