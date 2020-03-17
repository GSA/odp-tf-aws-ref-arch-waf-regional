// WAF
waf_prefix                            = "odp-waf-regional"
waf_blacklisted_ips                   = []
waf_admin_remote_ipset                = []
waf_alb_arn                           = ["arn:aws:elasticloadbalancing:us-east-1:496213958842:loadbalancer/app/odp-ra-alb/d83e69ff9e760713"]
waf_rule_size_restriction_action_type = "COUNT"
waf_rule_sqli_action                  = "COUNT"
waf_rule_xss_action                   = "COUNT"
waf_rule_lfi_rfi_action               = "COUNT"
waf_rule_ssi_action_type              = "COUNT"
waf_rule_auth_tokens_action           = "COUNT" #tfsec:ignore:GEN001
waf_rule_admin_access_action_type     = "COUNT"
waf_rule_php_insecurities_action_type = "COUNT"
waf_rule_csrf_action_type             = "COUNT"
waf_rule_blacklisted_ips_action_type  = "COUNT"