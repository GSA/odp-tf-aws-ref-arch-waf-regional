# odp-tf-aws-ref-arch-waf-regional

## Introduction <a name="s1"></a>

The `odp-tf-aws-ref-arch-waf-regional`  module is a web application firewall that helps protect GSA web applications or APIs against common web exploits that may affect availability, compromise security, or consume excessive resources.



## Table of Contents <a name="s2"></a>

* [Overview](#s1)
* [Module Contents](#s2)
* [Module Variables](#s3)
* [Module Output](#s4)
* [Example](#s5)
* [Resources Created](#s6)

## Overview <a name="s1"></a>
This Terraform module which creates AWF WAF resources for protection of your resources from the OWASP Top 10
Security Risks. This module is based on the whitepaper that AWS provides. The whitepaper tells how to use AWS WAF
to mitigate those attacks[[3]](https://d0.awsstatic.com/whitepapers/Security/aws-waf-owasp.pdf)[[4]](https://aws.amazon.com/about-aws/whats-new/2017/07/use-aws-waf-to-mitigate-owasps-top-10-web-application-vulnerabilities/).


**For more information:**
* AWS Blog - https://aws.amazon.com/about-aws/whats-new/2017/07/use-aws-waf-to-mitigate-owasps-top-10-web-application-vulnerabilities/

## Module Contents <a name="s2"></a>


| Folder / File      |  Description  |
|---          |---    |
| .circleci   | CI Pipeline code for validating module.  Requires working example in `example` directory. |
| main.tf   |   Main Terraform code |
| outputs.tf  |   Output variables |
| variables.tf  |   Required Variables |
| versions.tf   |   versions |
| waf-regional.tfvars  |   WAF input varaibels |
| wafregional_ruleset1_sqli.tf  |   SQL Injection Attacks Rules |
| wafregional_ruleset2_auth_tokens.tf   |   bad/hijacked JWT tokens or session IDs Rules  |
| wafregional_ruleset3_xss.tf      |  Cross Site Scripting Attacks Rules |
| wafregional_ruleset4_lfi_rfi.tf      |  Path Traversal, LFI, RFI Rules |
| wafregional_ruleset5_admin_access.tf     |  Privileged Module Access Restrictions Rules |
| wafregional_ruleset6_php_insecurities.tf      |  PHP Specific Security Misconfigurations Rules |
| wafregional_ruleset7_size_restriction.tf     |  Abnormal size request Rules |
| wafregional_ruleset8_csrf.tf      |  CSRF token enforcement Rules |
| wafregional_ruleset9_ssi.tf      |  Server-side includes & libraries in webroot Rules |
| wafregional_ruleset10_blacklisted_ips.tf      |  IP Blacklist |
| example/      |   Example  directory with sampel terraform |




## Module Variables <a name="s3"></a>

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| waf\_prefix | Prefix to use when naming resources | string | n/a | yes |
| waf_admin\_remote\_ipset | List of IPs allowed to access admin pages, ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32'] | list(string) | `[]` | no |
| waf_alb\_arn | List of ALB ARNs | list(string) | `[]` | no |
| waf_blacklisted\_ips | List of IPs to blacklist, eg ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32'] | list(string) | `[]` | no |
| waf_rule\_admin\_access\_action\_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_auth\_tokens\_action | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_blacklisted\_ips\_action\_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_csrf\_action\_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_lfi\_rfi\_action | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_php\_insecurities\_action\_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_size\_restriction\_action\_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_sqli\_action | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_ssi\_action\_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |
| waf_rule\_xss\_action | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"COUNT"` | no |

## Module Output <a name="s4"></a>

| Name | Description |
|------|-------------|
| web\_acl\_id | AWS WAF web acl id. |
| web\_acl\_metric\_name | The name or description for the Amazon CloudWatch metric of this web ACL. |
| web\_acl\_name | The name or description of the web ACL. |

## Example <a name="s5"></a>

```terraform
module "waf_regional_test" {
    source                              = "../"
    waf_prefix                          = "test"
    blacklisted_ips                     = []
    admin_remote_ipset                  = []
    alb_arn                             = []
    rule_size_restriction_action_type   = "COUNT"
    rule_sqli_action                    = "COUNT"
    rule_xss_action                     = "COUNT"
    rule_lfi_rfi_action                 = "COUNT"
    rule_ssi_action_type                = "COUNT"
    rule_auth_tokens_action             = "COUNT"
    rule_admin_access_action_type       = "COUNT"
    rule_php_insecurities_action_type   = "COUNT"
    rule_csrf_action_type               = "COUNT"
    rule_blacklisted_ips_action_type    = "COUNT"
}
```

## Resources Created <a name="s6"></a>

### Web ACL

A web access control list (web ACL) gives us fine-grained control over the web requests that Application Load Balancer responds to.

We can use criteria like the following to allow or block requests:
* IP address origin of the request
* Country of origin of the request
* String match or regular expression (regex) match in a part of the request
* Size of a particular part of the request
* Detection of malicious SQL code or scripting
### Web Rules (OWASP Top 10)
* Mitigate SQL Injection Attacks
* Blacklist bad/hijacked JWT tokens or session IDs
* Mitigate Cross Site Scripting Attacks
* Path Traversal, LFI, RFI
* Privileged Module Access Restrictions
* PHP Specific Security Misconfigurations
* Mitigate abnormal requests via size restrictions
* CSRF token enforcement
* Server-side includes & libraries in webroot
* IP Blacklist
### Web Conditions
* Cross-site scripting
* IP Addresses
* Size Constraints
* SQL Injection
* String and regex matching
