variable "name" {
  description = "Name prefix for all Network Firewall resources"
  type        = string

  validation {
    condition     = length(var.name) > 0 && length(var.name) <= 128
    error_message = "Name must be between 1 and 128 characters."
  }
}

variable "vpc_id" {
  description = "VPC ID where the Network Firewall will be deployed"
  type        = string

  validation {
    condition     = can(regex("^vpc-[a-z0-9]+$", var.vpc_id))
    error_message = "VPC ID must be a valid AWS VPC identifier (e.g., vpc-abc123)."
  }
}

variable "subnet_ids" {
  description = "Map of Availability Zone to subnet ID for firewall endpoint placement"
  type        = map(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "At least one subnet mapping must be provided."
  }
}

variable "firewall_policy_name" {
  description = "Name for the firewall policy. Defaults to var.name if not specified"
  type        = string
  default     = ""
}

variable "stateless_rule_groups" {
  description = "List of stateless rule group configurations"
  type = list(object({
    name     = string
    priority = number
    capacity = number
    rules = list(object({
      priority = number
      actions  = list(string)
      match_attributes = object({
        protocols   = optional(list(number), [])
        source      = optional(list(string), [])
        source_port = optional(list(string), [])
        destination = optional(list(string), [])
        destination_port = optional(list(string), [])
        tcp_flags = optional(list(object({
          flags = list(string)
          masks = optional(list(string), [])
        })), [])
      })
    }))
  }))
  default = []
}

variable "stateful_rule_groups" {
  description = "List of stateful rule group configurations"
  type = list(object({
    name           = string
    capacity       = number
    type           = string
    rules_string   = optional(string, "")
    domain_list    = optional(list(string), [])
    rule_variables = optional(map(list(string)), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for rg in var.stateful_rule_groups : contains(["SURICATA", "DOMAIN_LIST", "5TUPLE"], rg.type)
    ])
    error_message = "Stateful rule group type must be one of: SURICATA, DOMAIN_LIST, 5TUPLE."
  }
}

variable "stateless_default_actions" {
  description = "Default actions for stateless rules (aws:pass, aws:drop, aws:forward_to_sfe)"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]

  validation {
    condition = alltrue([
      for action in var.stateless_default_actions :
      contains(["aws:pass", "aws:drop", "aws:forward_to_sfe"], action)
    ])
    error_message = "Stateless default actions must be one of: aws:pass, aws:drop, aws:forward_to_sfe."
  }
}

variable "stateless_fragment_default_actions" {
  description = "Default actions for fragmented packets (aws:pass, aws:drop, aws:forward_to_sfe)"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]

  validation {
    condition = alltrue([
      for action in var.stateless_fragment_default_actions :
      contains(["aws:pass", "aws:drop", "aws:forward_to_sfe"], action)
    ])
    error_message = "Fragment default actions must be one of: aws:pass, aws:drop, aws:forward_to_sfe."
  }
}

variable "enable_logging" {
  description = "Enable logging for the Network Firewall"
  type        = bool
  default     = true
}

variable "log_destination_type" {
  description = "Destination type for firewall logs (s3 or cloudwatch)"
  type        = string
  default     = "cloudwatch"

  validation {
    condition     = contains(["s3", "cloudwatch"], var.log_destination_type)
    error_message = "Log destination type must be either 's3' or 'cloudwatch'."
  }
}

variable "log_types" {
  description = "Types of logs to enable (ALERT and/or FLOW)"
  type        = list(string)
  default     = ["ALERT", "FLOW"]

  validation {
    condition = alltrue([
      for lt in var.log_types : contains(["ALERT", "FLOW"], lt)
    ])
    error_message = "Log types must be ALERT and/or FLOW."
  }
}

variable "deletion_protection" {
  description = "Enable deletion protection for the firewall"
  type        = bool
  default     = false
}

variable "encryption_type" {
  description = "Encryption configuration type (AWS_OWNED_KMS_KEY or CUSTOMER_KMS)"
  type        = string
  default     = "AWS_OWNED_KMS_KEY"

  validation {
    condition     = contains(["AWS_OWNED_KMS_KEY", "CUSTOMER_KMS"], var.encryption_type)
    error_message = "Encryption type must be AWS_OWNED_KMS_KEY or CUSTOMER_KMS."
  }
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encryption. Required when encryption_type is CUSTOMER_KMS"
  type        = string
  default     = null
}

variable "tags" {
  description = "Map of tags to apply to all resources"
  type        = map(string)
  default     = {}
}
