# Complete Example - Centralized Inspection VPC Pattern

This example demonstrates the centralized inspection VPC architecture using AWS Network Firewall with Transit Gateway for enterprise-grade network security.

## Architecture

```
                        Internet
                           |
                      [Internet GW]
                           |
                     [Public Subnets]
                      [NAT Gateways]
                           |
                    [Firewall Subnets]
                  [Network Firewall Endpoints]
                           |
                   [TGW Attachment Subnets]
                           |
                    [Transit Gateway]
                      /          \
              [Spoke VPC A]   [Spoke VPC B]
              10.1.0.0/16     10.2.0.0/16
```

All traffic between spoke VPCs and egress traffic to the internet is routed through the centralized inspection VPC where AWS Network Firewall performs deep packet inspection.

## What This Creates

### Inspection VPC (10.0.0.0/16)
- Firewall subnets with Network Firewall endpoints
- TGW attachment subnets
- Public subnets with NAT Gateways and Internet Gateway
- Route tables directing traffic through firewall endpoints

### Transit Gateway
- Separate route tables for inspection and spoke VPCs
- Appliance mode enabled on inspection VPC attachment
- Default route in spoke route table pointing to inspection VPC

### Spoke VPCs
- Spoke A (10.1.0.0/16) and Spoke B (10.2.0.0/16)
- All traffic routed to Transit Gateway
- Propagated routes to inspection route table

### Security Rules
- Stateless blocking of high-risk protocols (Telnet, RDP)
- Suricata rules for SSH brute force, port scanning, malware downloads, C2 detection, DNS tunneling, TOR blocking, and lateral movement detection
- Domain-based filtering for known malicious domains
- S3 logging for ALERT and FLOW logs with lifecycle policies

## Usage

```bash
terraform init
terraform plan
terraform apply
```

## Important Notes

- **Appliance Mode**: Enabled on the inspection VPC TGW attachment to ensure symmetric routing
- **Deletion Protection**: Enabled on the firewall to prevent accidental deletion
- **Cost**: Each firewall endpoint costs approximately $0.395/hr plus $0.065/GB of data processed
- **HA**: Firewall endpoints are deployed across two Availability Zones

## Outputs

| Name | Description |
|------|-------------|
| firewall_id | Network Firewall ID |
| firewall_arn | Network Firewall ARN |
| firewall_endpoints | Map of AZ to firewall endpoint IDs |
| transit_gateway_id | Transit Gateway ID |
| inspection_vpc_id | Inspection VPC ID |
| spoke_a_vpc_id | Spoke A VPC ID |
| spoke_b_vpc_id | Spoke B VPC ID |
