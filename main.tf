resource "aws_wafregional_web_acl" "wafregional_acl" {
  name        = "${var.waf_prefix}-generic-owasp-acl"
  metric_name = replace("${var.waf_prefix}genericowaspacl", "/[^0-9A-Za-z]/", "")

  default_action {
    type = "ALLOW"
  }

  rule {
    action {
      type = var.waf_rule_size_restriction_action_type
    }

    priority = 10
    rule_id  = aws_wafregional_rule.restrict_sizes.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_blacklisted_ips_action_type
    }

    priority = 20
    rule_id  = aws_wafregional_rule.detect_blacklisted_ips.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_auth_tokens_action
    }

    priority = 30
    rule_id  = aws_wafregional_rule.detect_bad_auth_tokens.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_sqli_action
    }

    priority = 40
    rule_id  = aws_wafregional_rule.mitigate_sqli.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_xss_action
    }

    priority = 50
    rule_id  = aws_wafregional_rule.mitigate_xss.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_lfi_rfi_action
    }

    priority = 60
    rule_id  = aws_wafregional_rule.detect_rfi_lfi_traversal.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_php_insecurities_action_type
    }

    priority = 70
    rule_id  = aws_wafregional_rule.detect_php_insecure.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_csrf_action_type
    }

    priority = 80
    rule_id  = aws_wafregional_rule.enforce_csrf.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_ssi_action_type
    }

    priority = 90
    rule_id  = aws_wafregional_rule.detect_ssi.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.waf_rule_admin_access_action_type
    }

    priority = 100
    rule_id  = aws_wafregional_rule.detect_admin_access.id
    type     = "REGULAR"
  }
}

#
# Link the WAF ACL to an ALBs.
#
resource "aws_wafregional_web_acl_association" "acl_alb_association" {
  depends_on   = [aws_wafregional_web_acl.wafregional_acl]
  count        = length(var.waf_alb_arn)
  resource_arn = var.waf_alb_arn[count.index]
  web_acl_id   = aws_wafregional_web_acl.wafregional_acl.id
}

