################################################################################
# Network Firewall
################################################################################

resource "aws_networkfirewall_firewall" "this" {
  name                              = var.name
  firewall_policy_arn               = aws_networkfirewall_firewall_policy.this.arn
  vpc_id                            = var.vpc_id
  delete_protection                 = var.deletion_protection
  firewall_policy_change_protection = var.deletion_protection
  subnet_change_protection          = var.deletion_protection

  dynamic "subnet_mapping" {
    for_each = var.subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }

  dynamic "encryption_configuration" {
    for_each = var.encryption_type == "CUSTOMER_KMS" ? [1] : []
    content {
      type   = "CUSTOMER_KMS"
      key_id = var.kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name = var.name
  })
}

################################################################################
# Firewall Policy
################################################################################

resource "aws_networkfirewall_firewall_policy" "this" {
  name = var.firewall_policy_name != "" ? var.firewall_policy_name : "${var.name}-policy"

  firewall_policy {
    stateless_default_actions          = var.stateless_default_actions
    stateless_fragment_default_actions = var.stateless_fragment_default_actions

    dynamic "stateless_rule_group_reference" {
      for_each = aws_networkfirewall_rule_group.stateless
      content {
        priority     = var.stateless_rule_groups[stateless_rule_group_reference.key].priority
        resource_arn = stateless_rule_group_reference.value.arn
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = aws_networkfirewall_rule_group.suricata
      content {
        resource_arn = stateful_rule_group_reference.value.arn
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = aws_networkfirewall_rule_group.domain
      content {
        resource_arn = stateful_rule_group_reference.value.arn
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = aws_networkfirewall_rule_group.five_tuple
      content {
        resource_arn = stateful_rule_group_reference.value.arn
      }
    }

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }
  }

  dynamic "encryption_configuration" {
    for_each = var.encryption_type == "CUSTOMER_KMS" ? [1] : []
    content {
      type   = "CUSTOMER_KMS"
      key_id = var.kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name = var.firewall_policy_name != "" ? var.firewall_policy_name : "${var.name}-policy"
  })
}

################################################################################
# Stateless Rule Groups
################################################################################

resource "aws_networkfirewall_rule_group" "stateless" {
  count = length(var.stateless_rule_groups)

  name     = var.stateless_rule_groups[count.index].name
  capacity = var.stateless_rule_groups[count.index].capacity
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        dynamic "stateless_rule" {
          for_each = var.stateless_rule_groups[count.index].rules
          content {
            priority = stateless_rule.value.priority

            rule_definition {
              actions = stateless_rule.value.actions

              match_attributes {
                dynamic "source" {
                  for_each = stateless_rule.value.match_attributes.source
                  content {
                    address_definition = source.value
                  }
                }

                dynamic "destination" {
                  for_each = stateless_rule.value.match_attributes.destination
                  content {
                    address_definition = destination.value
                  }
                }

                dynamic "source_port" {
                  for_each = stateless_rule.value.match_attributes.source_port
                  content {
                    from_port = tonumber(split("-", source_port.value)[0])
                    to_port   = tonumber(element(split("-", source_port.value), length(split("-", source_port.value)) - 1))
                  }
                }

                dynamic "destination_port" {
                  for_each = stateless_rule.value.match_attributes.destination_port
                  content {
                    from_port = tonumber(split("-", destination_port.value)[0])
                    to_port   = tonumber(element(split("-", destination_port.value), length(split("-", destination_port.value)) - 1))
                  }
                }

                protocols = stateless_rule.value.match_attributes.protocols

                dynamic "tcp_flag" {
                  for_each = stateless_rule.value.match_attributes.tcp_flags
                  content {
                    flags = tcp_flag.value.flags
                    masks = length(tcp_flag.value.masks) > 0 ? tcp_flag.value.masks : tcp_flag.value.flags
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  dynamic "encryption_configuration" {
    for_each = var.encryption_type == "CUSTOMER_KMS" ? [1] : []
    content {
      type   = "CUSTOMER_KMS"
      key_id = var.kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name = var.stateless_rule_groups[count.index].name
  })
}

################################################################################
# Stateful Rule Groups - Suricata
################################################################################

resource "aws_networkfirewall_rule_group" "suricata" {
  count = length([for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"])

  name     = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].name
  capacity = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].capacity
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].rules_string
    }

    dynamic "rule_variables" {
      for_each = length([for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].rule_variables) > 0 ? [1] : []
      content {
        dynamic "ip_sets" {
          for_each = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].rule_variables
          content {
            key = ip_sets.key
            ip_set {
              definition = ip_sets.value
            }
          }
        }
      }
    }

    stateful_rule_options {
      capacity = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].capacity
    }
  }

  dynamic "encryption_configuration" {
    for_each = var.encryption_type == "CUSTOMER_KMS" ? [1] : []
    content {
      type   = "CUSTOMER_KMS"
      key_id = var.kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name = [for rg in var.stateful_rule_groups : rg if rg.type == "SURICATA"][count.index].name
  })
}

################################################################################
# Stateful Rule Groups - Domain Filtering
################################################################################

resource "aws_networkfirewall_rule_group" "domain" {
  count = length([for rg in var.stateful_rule_groups : rg if rg.type == "DOMAIN_LIST"])

  name     = [for rg in var.stateful_rule_groups : rg if rg.type == "DOMAIN_LIST"][count.index].name
  capacity = [for rg in var.stateful_rule_groups : rg if rg.type == "DOMAIN_LIST"][count.index].capacity
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "DENYLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = [for rg in var.stateful_rule_groups : rg if rg.type == "DOMAIN_LIST"][count.index].domain_list
      }
    }
  }

  dynamic "encryption_configuration" {
    for_each = var.encryption_type == "CUSTOMER_KMS" ? [1] : []
    content {
      type   = "CUSTOMER_KMS"
      key_id = var.kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name = [for rg in var.stateful_rule_groups : rg if rg.type == "DOMAIN_LIST"][count.index].name
  })
}

################################################################################
# Stateful Rule Groups - 5-Tuple
################################################################################

resource "aws_networkfirewall_rule_group" "five_tuple" {
  count = length([for rg in var.stateful_rule_groups : rg if rg.type == "5TUPLE"])

  name     = [for rg in var.stateful_rule_groups : rg if rg.type == "5TUPLE"][count.index].name
  capacity = [for rg in var.stateful_rule_groups : rg if rg.type == "5TUPLE"][count.index].capacity
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = [for rg in var.stateful_rule_groups : rg if rg.type == "5TUPLE"][count.index].rules_string
    }
  }

  dynamic "encryption_configuration" {
    for_each = var.encryption_type == "CUSTOMER_KMS" ? [1] : []
    content {
      type   = "CUSTOMER_KMS"
      key_id = var.kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name = [for rg in var.stateful_rule_groups : rg if rg.type == "5TUPLE"][count.index].name
  })
}

################################################################################
# CloudWatch Log Groups
################################################################################

resource "aws_cloudwatch_log_group" "firewall" {
  for_each = var.enable_logging && var.log_destination_type == "cloudwatch" ? {
    for lt in var.log_types : lt => "/aws/network-firewall/${var.name}/${lower(lt)}"
  } : {}

  name              = each.value
  retention_in_days = 90

  tags = merge(var.tags, {
    Name    = each.value
    LogType = each.key
  })
}

################################################################################
# S3 Bucket for Log Storage
################################################################################

resource "aws_s3_bucket" "firewall_logs" {
  count = var.enable_logging && var.log_destination_type == "s3" ? 1 : 0

  bucket        = "${var.name}-firewall-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, {
    Name = "${var.name}-firewall-logs-${data.aws_caller_identity.current.account_id}"
  })
}

resource "aws_s3_bucket_versioning" "firewall_logs" {
  count = var.enable_logging && var.log_destination_type == "s3" ? 1 : 0

  bucket = aws_s3_bucket.firewall_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firewall_logs" {
  count = var.enable_logging && var.log_destination_type == "s3" ? 1 : 0

  bucket = aws_s3_bucket.firewall_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.encryption_type == "CUSTOMER_KMS" ? "aws:kms" : "AES256"
      kms_master_key_id = var.encryption_type == "CUSTOMER_KMS" ? var.kms_key_arn : null
    }
    bucket_key_enabled = var.encryption_type == "CUSTOMER_KMS" ? true : false
  }
}

resource "aws_s3_bucket_public_access_block" "firewall_logs" {
  count = var.enable_logging && var.log_destination_type == "s3" ? 1 : 0

  bucket = aws_s3_bucket.firewall_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "firewall_logs" {
  count = var.enable_logging && var.log_destination_type == "s3" ? 1 : 0

  bucket = aws_s3_bucket.firewall_logs[0].id

  rule {
    id     = "log-lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

################################################################################
# Logging Configuration
################################################################################

resource "aws_networkfirewall_logging_configuration" "this" {
  count = var.enable_logging ? 1 : 0

  firewall_arn = aws_networkfirewall_firewall.this.arn

  logging_configuration {
    dynamic "log_destination_config" {
      for_each = {
        for lt in var.log_types : lt => {
          log_type             = lt
          log_destination_type = var.log_destination_type == "s3" ? "S3" : "CloudWatchLogs"
        }
      }
      content {
        log_destination_type = log_destination_config.value.log_destination_type
        log_type             = log_destination_config.value.log_type

        log_destination = var.log_destination_type == "s3" ? {
          bucketName = aws_s3_bucket.firewall_logs[0].id
          prefix     = "network-firewall/${lower(log_destination_config.value.log_type)}"
        } : {
          logGroup = aws_cloudwatch_log_group.firewall[log_destination_config.key].name
        }
      }
    }
  }
}
