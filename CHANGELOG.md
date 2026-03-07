# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-01

### Added

- AWS Network Firewall resource with multi-AZ subnet mappings
- Firewall policy with stateful strict order and configurable stateless actions
- Stateless rule groups for L3/L4 packet filtering
- Stateful rule groups with Suricata IDS/IPS rules support
- Domain filtering rule groups for HTTP Host and TLS SNI inspection
- 5-tuple stateful rule group support
- Configurable logging to CloudWatch Logs or S3
- S3 bucket with versioning, encryption, lifecycle policies, and public access blocking
- CloudWatch log groups with configurable retention
- KMS encryption support (AWS-owned or customer-managed keys)
- Deletion protection for production deployments
- Basic example with stateless rules
- Advanced example with Suricata rules and domain filtering
- Complete example with centralized inspection VPC and Transit Gateway pattern
- Comprehensive documentation with architecture diagrams

[1.0.0]: https://github.com/kogunlowo123/terraform-aws-network-firewall/releases/tag/v1.0.0
