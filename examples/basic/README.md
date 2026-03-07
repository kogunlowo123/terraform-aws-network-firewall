# Basic Network Firewall Example

This example deploys an AWS Network Firewall with simple stateless rules for ICMP blocking and HTTPS allowlisting.

## What This Creates

- A VPC with two firewall subnets across Availability Zones
- An AWS Network Firewall with stateless rule groups
- CloudWatch log groups for ALERT and FLOW logs

## Usage

```bash
terraform init
terraform plan
terraform apply
```

## Inputs

This example does not require any input variables. All values are hardcoded for demonstration purposes.

## Outputs

| Name | Description |
|------|-------------|
| firewall_arn | ARN of the deployed Network Firewall |
| endpoint_ids | Map of AZ to firewall endpoint IDs |
