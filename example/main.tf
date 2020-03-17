provider "aws" {
  region = "us-east-1"
}

module "waf-regional" {
  source                                = "../"
  waf_prefix                            = "odp-example"
  waf_blacklisted_ips                   = []
  waf_admin_remote_ipset                = []
  waf_alb_arn                           = []
  waf_rule_size_restriction_action_type = "COUNT"
  waf_rule_sqli_action                  = "COUNT"
  waf_rule_xss_action                   = "COUNT"
  waf_rule_lfi_rfi_action               = "COUNT"
  waf_rule_ssi_action_type              = "COUNT"
  waf_rule_auth_tokens_action           = "COUNT" #tfsec:ignore:GEN003
  waf_rule_admin_access_action_type     = "COUNT"
  waf_rule_php_insecurities_action_type = "COUNT"
  waf_rule_csrf_action_type             = "COUNT"
  waf_rule_blacklisted_ips_action_type  = "COUNT"
}
