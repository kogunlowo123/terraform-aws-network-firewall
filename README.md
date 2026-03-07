# terraform-aws-network-firewall

Production-ready Terraform module for deploying AWS Network Firewall with stateful/stateless rule groups, Suricata IDS/IPS rules, domain filtering, and centralized inspection VPC pattern support.

## Architecture

### Centralized Inspection VPC Pattern

```
                              Internet
                                 |
                          +------+------+
                          | Internet GW |
                          +------+------+
                                 |
                       +---------+---------+
                       |   Public Subnets  |
                       |   (NAT Gateways)  |
                       +---------+---------+
                                 |
                       +---------+---------+
                       | Firewall Subnets  |
                       |  (Network FW      |
                       |   Endpoints)      |
                       +---------+---------+
                                 |
                       +---------+---------+
                       |  TGW Attachment   |
                       |     Subnets       |
                       +---------+---------+
                                 |
                       +---------+---------+
                       |  Transit Gateway  |
                       +---------+---------+
                          /      |      \
                   +------+  +---+---+  +------+
                   |Spoke |  |Spoke  |  |Spoke |
                   |VPC A |  |VPC B  |  |VPC C |
                   +------+  +-------+  +------+
```

All inter-VPC and egress traffic flows through the centralized inspection VPC where AWS Network Firewall performs deep packet inspection using stateless L3/L4 rules, Suricata-compatible IDS/IPS signatures, and domain-based filtering.

## Features

- **Multi-AZ Deployment** - Firewall endpoints across multiple Availability Zones for high availability
- **Stateless Rule Groups** - L3/L4 packet filtering with configurable match attributes (protocols, ports, CIDRs, TCP flags)
- **Suricata IDS/IPS Rules** - Full Suricata-compatible rule engine for deep packet inspection and threat detection
- **Domain Filtering** - Block or allow domains via HTTP Host header and TLS SNI inspection
- **5-Tuple Rules** - Traditional stateful firewall rules with source/destination IP, port, and protocol matching
- **Strict Rule Ordering** - Stateful engine configured with strict order for predictable rule evaluation
- **Flexible Logging** - Send ALERT and FLOW logs to CloudWatch Logs or S3
- **S3 Log Management** - Automatic bucket creation with versioning, encryption, lifecycle policies, and public access blocking
- **KMS Encryption** - Support for AWS-owned or customer-managed KMS keys
- **Deletion Protection** - Configurable protection against accidental firewall deletion

## Usage

### Basic - Stateless Rules

```hcl
module "network_firewall" {
  source = "kogunlowo123/network-firewall/aws"

  name   = "my-firewall"
  vpc_id = "vpc-abc123"

  subnet_ids = {
    "us-east-1a" = "subnet-111"
    "us-east-1b" = "subnet-222"
  }

  stateless_rule_groups = [
    {
      name     = "block-icmp"
      priority = 1
      capacity = 100
      rules = [
        {
          priority = 1
          actions  = ["aws:drop"]
          match_attributes = {
            protocols   = [1]
            source      = ["0.0.0.0/0"]
            destination = ["0.0.0.0/0"]
          }
        }
      ]
    }
  ]
}
```

### Advanced - Suricata Rules and Domain Filtering

```hcl
module "network_firewall" {
  source = "kogunlowo123/network-firewall/aws"

  name   = "advanced-firewall"
  vpc_id = "vpc-abc123"

  subnet_ids = {
    "us-east-1a" = "subnet-111"
    "us-east-1b" = "subnet-222"
  }

  stateful_rule_groups = [
    {
      name     = "suricata-rules"
      capacity = 200
      type     = "SURICATA"
      rules_string = <<-EOT
        drop ssh any any -> $HOME_NET 22 (msg:"SSH brute force"; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)
        drop tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555] (msg:"C2 blocked"; sid:1000002; rev:1;)
      EOT
      rule_variables = {
        HOME_NET     = ["10.0.0.0/16"]
        EXTERNAL_NET = ["0.0.0.0/0"]
      }
    },
    {
      name     = "domain-blocklist"
      capacity = 100
      type     = "DOMAIN_LIST"
      domain_list = [
        ".malware-domain.com",
        ".phishing-site.net"
      ]
    }
  ]

  enable_logging       = true
  log_destination_type = "s3"
  log_types            = ["ALERT", "FLOW"]
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.20.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| name | Name prefix for all Network Firewall resources | `string` | n/a | yes |
| vpc_id | VPC ID where the Network Firewall will be deployed | `string` | n/a | yes |
| subnet_ids | Map of Availability Zone to subnet ID for firewall endpoint placement | `map(string)` | n/a | yes |
| firewall_policy_name | Name for the firewall policy | `string` | `""` | no |
| stateless_rule_groups | List of stateless rule group configurations | `list(object)` | `[]` | no |
| stateful_rule_groups | List of stateful rule group configurations (SURICATA, DOMAIN_LIST, 5TUPLE) | `list(object)` | `[]` | no |
| stateless_default_actions | Default actions for stateless rules | `list(string)` | `["aws:forward_to_sfe"]` | no |
| stateless_fragment_default_actions | Default actions for fragmented packets | `list(string)` | `["aws:forward_to_sfe"]` | no |
| enable_logging | Enable logging for the Network Firewall | `bool` | `true` | no |
| log_destination_type | Destination type for firewall logs (s3 or cloudwatch) | `string` | `"cloudwatch"` | no |
| log_types | Types of logs to enable (ALERT and/or FLOW) | `list(string)` | `["ALERT", "FLOW"]` | no |
| deletion_protection | Enable deletion protection for the firewall | `bool` | `false` | no |
| encryption_type | Encryption configuration type (AWS_OWNED_KMS_KEY or CUSTOMER_KMS) | `string` | `"AWS_OWNED_KMS_KEY"` | no |
| kms_key_arn | ARN of the KMS key for encryption (required when encryption_type is CUSTOMER_KMS) | `string` | `null` | no |
| tags | Map of tags to apply to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| firewall_id | The unique identifier of the Network Firewall |
| firewall_arn | The ARN of the Network Firewall |
| firewall_status | The current status of the Network Firewall |
| endpoint_ids | Map of Availability Zone to VPC endpoint ID for the firewall |
| policy_arn | The ARN of the firewall policy |
| logging_configuration_id | The ID of the logging configuration |

## Examples

- [Basic](examples/basic/) - Simple firewall with stateless rules
- [Advanced](examples/advanced/) - Full firewall with Suricata rules and domain filtering
- [Complete](examples/complete/) - Centralized inspection VPC pattern with Transit Gateway integration

## Security Considerations

1. **Defense in Depth**: Use Network Firewall alongside Security Groups and NACLs for layered security
2. **Rule Ordering**: Stateful rules use strict ordering - ensure rules are prioritized correctly
3. **Suricata Rules**: Test Suricata rules in alert-only mode before switching to drop actions
4. **Domain Filtering**: Domain lists inspect HTTP Host headers and TLS SNI; does not decrypt TLS traffic
5. **Logging**: Always enable both ALERT and FLOW logs for forensic analysis and compliance
6. **Encryption**: Use customer-managed KMS keys for sensitive environments requiring key rotation control
7. **Appliance Mode**: Enable appliance mode on Transit Gateway attachments for symmetric routing
8. **Deletion Protection**: Enable in production to prevent accidental firewall deletion

## Cost Estimation

AWS Network Firewall pricing (us-east-1, subject to change):

| Component | Cost |
|-----------|------|
| Firewall endpoint (per AZ) | ~$0.395/hour (~$288/month) |
| Data processed | ~$0.065/GB |

**Example**: 2-AZ deployment processing 1 TB/month:
- Endpoints: 2 x $288 = $576/month
- Data processing: 1000 GB x $0.065 = $65/month
- **Total: ~$641/month**

## References

- [AWS Network Firewall Documentation](https://docs.aws.amazon.com/network-firewall/latest/developerguide/)
- [AWS Network Firewall Pricing](https://aws.amazon.com/network-firewall/pricing/)
- [Suricata Rules Format](https://suricata.readthedocs.io/en/latest/rules/)
- [Centralized Inspection Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/inline-traffic-inspection-third-party-appliances/)
- [Terraform AWS Network Firewall Resources](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_firewall)

## License

MIT Licensed. See [LICENSE](LICENSE) for full details.
