locals {
  firewall_policy_name = var.firewall_policy_name != "" ? var.firewall_policy_name : "${var.name}-policy"

  common_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Module    = "terraform-aws-network-firewall"
  })

  # Separate stateful rule groups by type
  suricata_rule_groups    = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"]
  domain_list_rule_groups = [for rg in var.stateful_rule_groups : rg if rg.type == "DOMAIN_LIST"]
  five_tuple_rule_groups  = [for rg in var.stateful_rule_groups : rg if rg.type == "5TUPLE"]

  # Build log destination configurations
  log_configs = var.enable_logging ? {
    for lt in var.log_types : lt => {
      log_type             = lt
      log_destination_type = var.log_destination_type == "s3" ? "S3" : "CloudWatchLogs"
    }
  } : {}

  # CloudWatch log group names
  cloudwatch_log_groups = var.enable_logging && var.log_destination_type == "cloudwatch" ? {
    for lt in var.log_types : lt => "/aws/network-firewall/${var.name}/${lower(lt)}"
  } : {}

  # S3 bucket name
  s3_bucket_name = var.enable_logging && var.log_destination_type == "s3" ? "${var.name}-firewall-logs-${data.aws_caller_identity.current.account_id}" : ""

  # Firewall endpoint IDs mapped by AZ
  firewall_endpoint_ids = {
    for sync_state in try(aws_networkfirewall_firewall.this.firewall_status[0].sync_states, []) :
    sync_state.availability_zone => sync_state.attachment[0].endpoint_id
  }
}
