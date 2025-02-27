---
page_title: "Resource: auth0_email_template"
description: |-
  With Auth0, you can have standard welcome, password reset, and account verification email-based workflows built right into Auth0. This resource allows you to configure email templates to customize the look, feel, and sender identities of emails sent by Auth0. Used in conjunction with configured email providers.
---

# Resource: auth0_email_template

With Auth0, you can have standard welcome, password reset, and account verification email-based workflows built right into Auth0. This resource allows you to configure email templates to customize the look, feel, and sender identities of emails sent by Auth0. Used in conjunction with configured email providers.

## Example Usage

```terraform
resource "auth0_email_provider" "my_email_provider" {
  name                 = "ses"
  enabled              = true
  default_from_address = "accounts@example.com"

  credentials {
    access_key_id     = "AKIAXXXXXXXXXXXXXXXX"
    secret_access_key = "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    region            = "us-east-1"
  }
}

resource "auth0_email_template" "my_email_template" {
  depends_on = [auth0_email_provider.my_email_provider]

  template                = "welcome_email"
  body                    = "<html><body><h1>Welcome!</h1></body></html>"
  from                    = "welcome@example.com"
  result_url              = "https://example.com/welcome"
  subject                 = "Welcome"
  syntax                  = "liquid"
  url_lifetime_in_seconds = 3600
  enabled                 = true
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `body` (String) Body of the email template. You can include [common variables](https://auth0.com/docs/customize/email/email-templates#common-variables).
- `enabled` (Boolean) Indicates whether the template is enabled.
- `from` (String) Email address to use as the sender. You can include [common variables](https://auth0.com/docs/customize/email/email-templates#common-variables).
- `subject` (String) Subject line of the email. You can include [common variables](https://auth0.com/docs/customize/email/email-templates#common-variables).
- `syntax` (String) Syntax of the template body. You can use either text or HTML with Liquid syntax.
- `template` (String) Template name. Options include `verify_email`, `verify_email_by_code`, `reset_email`, `reset_email_by_code`, `welcome_email`, `blocked_account`, `stolen_credentials`, `enrollment_email`, `mfa_oob_code`, `user_invitation`, `change_password` (legacy), or `password_reset` (legacy).

### Optional

- `include_email_in_redirect` (Boolean) Whether the `reset_email` and `verify_email` templates should include the user's email address as the email parameter in the `returnUrl` (true) or whether no email address should be included in the redirect (false). Defaults to `true`.
- `result_url` (String) URL to redirect the user to after a successful action. [Learn more](https://auth0.com/docs/customize/email/email-templates#configure-template-fields).
- `url_lifetime_in_seconds` (Number) Number of seconds during which the link within the email will be valid.

### Read-Only

- `id` (String) The ID of this resource.

## Import

Import is supported using the following syntax:

```shell
# This resource can be imported using the pre-defined template name.
#
# These names are `verify_email`, `verify_email_by_code`, `reset_email`,
# `welcome_email`, `blocked_account`, `stolen_credentials`,
# `enrollment_email`, `mfa_oob_code`, and `user_invitation`.
#
# The names `change_password`, and `password_reset` are also supported
# for legacy scenarios.
#
# Example:
terraform import auth0_email_template.my_email_template "welcome_email"
```
