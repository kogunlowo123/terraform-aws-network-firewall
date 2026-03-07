output "firewall_id" {
  description = "The unique identifier of the Network Firewall"
  value       = aws_networkfirewall_firewall.this.id
}

output "firewall_arn" {
  description = "The ARN of the Network Firewall"
  value       = aws_networkfirewall_firewall.this.arn
}

output "firewall_status" {
  description = "The current status of the Network Firewall"
  value       = aws_networkfirewall_firewall.this.firewall_status
}

output "endpoint_ids" {
  description = "Map of Availability Zone to VPC endpoint ID for the firewall"
  value       = local.firewall_endpoint_ids
}

output "policy_arn" {
  description = "The ARN of the firewall policy"
  value       = aws_networkfirewall_firewall_policy.this.arn
}

output "logging_configuration_id" {
  description = "The ID of the logging configuration"
  value       = var.enable_logging ? aws_networkfirewall_logging_configuration.this[0].id : null
}
