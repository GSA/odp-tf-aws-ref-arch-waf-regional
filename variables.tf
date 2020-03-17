variable "waf_prefix" {
  description = "Prefix to use when naming resources"
}

variable "waf_blacklisted_ips" {
  default     = []
  type        = list(string)
  description = "List of IPs to blacklist, eg ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32']"
}

variable "waf_admin_remote_ipset" {
  default     = []
  type        = list(string)
  description = "List of IPs allowed to access admin pages, ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32']"
}

variable "waf_alb_arn" {
  default     = []
  type        = list(string)
  description = "List of ALB ARNs"
}

variable "waf_rule_sqli_action" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_auth_tokens_action" {
  default     = "COUNT" #tfsec:ignore:GEN001
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_xss_action" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_lfi_rfi_action" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_admin_access_action_type" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_php_insecurities_action_type" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_size_restriction_action_type" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_csrf_action_type" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_ssi_action_type" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "waf_rule_blacklisted_ips_action_type" {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}
