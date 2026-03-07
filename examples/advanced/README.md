# Advanced Network Firewall Example

This example deploys an AWS Network Firewall with Suricata IDS/IPS rules and domain filtering for comprehensive threat detection.

## What This Creates

- A VPC with firewall subnets across two Availability Zones
- An AWS Network Firewall with both stateless and stateful rule groups
- Suricata-based threat detection rules (SSH brute force, suspicious user agents, C2 detection, crypto mining)
- Domain-based filtering to block known malicious domains
- CloudWatch logging for ALERT and FLOW logs

## Usage

```bash
terraform init
terraform plan
terraform apply
```

## Security Rules

### Stateless Rules
- Blocks Telnet (port 23), RDP (port 3389), and SMB (port 445) traffic
- Drops all fragmented packets

### Suricata Rules
- Detects SSH brute force attempts (5+ attempts in 60 seconds)
- Alerts on suspicious HTTP user agents
- Blocks outbound connections to common C2 ports
- Alerts on DNS TXT queries (potential data exfiltration)
- Blocks cryptocurrency mining pool connections

### Domain Filtering
- Blocks access to known malicious domains via HTTP Host header and TLS SNI inspection

## Outputs

| Name | Description |
|------|-------------|
| firewall_id | Unique identifier of the Network Firewall |
| firewall_arn | ARN of the deployed Network Firewall |
| policy_arn | ARN of the firewall policy |
| endpoint_ids | Map of AZ to firewall endpoint IDs |
