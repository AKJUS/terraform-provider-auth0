---
page_title: "Resource: auth0_email_provider"
description: |-
  With Auth0, you can have standard welcome, password reset, and account verification email-based workflows built right into Auth0. This resource allows you to configure email providers, so you can route all emails that are part of Auth0's authentication workflows through the supported high-volume email service of your choice.
---

# Resource: auth0_email_provider

With Auth0, you can have standard welcome, password reset, and account verification email-based workflows built right into Auth0. This resource allows you to configure email providers, so you can route all emails that are part of Auth0's authentication workflows through the supported high-volume email service of your choice.

!> This resource manages to create a max of 1 email provider for a tenant.
To avoid potential issues, it is recommended not to try creating multiple email providers on the same tenant.

!> If you are using the `auth0_email_provider` resource to create a `custom` email provider, you must ensure an action is created first with `custom-email-provider` as the supported_triggers


## Example Usage

```terraform
# This is an example on how to set up the email provider with Amazon SES.
resource "auth0_email_provider" "amazon_ses_email_provider" {
  name                 = "ses"
  enabled              = true
  default_from_address = "accounts@example.com"

  credentials {
    access_key_id     = "AKIAXXXXXXXXXXXXXXXX"
    secret_access_key = "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    region            = "us-east-1"
  }
}

# This is an example on how to set up the email provider with SMTP.
resource "auth0_email_provider" "smtp_email_provider" {
  name                 = "smtp"
  enabled              = true
  default_from_address = "accounts@example.com"

  credentials {
    smtp_host = "your.smtp.host.com"
    smtp_port = 583
    smtp_user = "SMTP Username"
    smtp_pass = "SMTP Password"
  }
}

# This is an example on how to set up the email provider with Sendgrid.
resource "auth0_email_provider" "sendgrid_email_provider" {
  name                 = "sendgrid"
  enabled              = true
  default_from_address = "accounts@example.com"

  credentials {
    api_key = "secretAPIKey"
  }
}


# This is an example on how to set up the email provider with Azure CS.
resource "auth0_email_provider" "azure_cs_email_provider" {
  name                 = "azure_cs"
  enabled              = true
  default_from_address = "accounts@example.com"

  credentials {
    azure_cs_connection_string = "azure_cs_connection_string"
  }
}


# This is an example on how to set up the email provider with MS365.
resource "auth0_email_provider" "ms365_email_provider" {
  name                 = "ms365"
  enabled              = true
  default_from_address = "accounts@example.com"

  credentials {
    ms365_tenant_id     = "ms365_tenant_id"
    ms365_client_id     = "ms365_client_id"
    ms365_client_secret = "ms365_client_secret"
  }
}

# Below is an example of how to set up a custom email provider.
# The action with custom-email-provider as supported_triggers is a prerequisite.
resource "auth0_action" "custom_email_provider_action" {
  name    = "custom-email-provider-action"
  runtime = "node18"
  deploy  = true
  code    = <<-EOT
  /**
   * Handler to be executed while sending an email notification.
   *
   * @param {Event} event - Details about the user and the context in which they are logging in.
   * @param {CustomEmailProviderAPI} api - Methods and utilities to help change the behavior of sending a email notification.
   */
   exports.onExecuteCustomEmailProvider = async (event, api) => {
    // Code goes here
    console.log(event);
    return;
   };
  EOT

  supported_triggers {
    id      = "custom-email-provider"
    version = "v1"
  }
}

resource "auth0_email_provider" "custom_email_provider" {
  depends_on           = [auth0_action.custom_email_provider_action] # Ensuring the action is created first with `custom-email-provider` as the supported_triggers
  name                 = "custom"                                    # Indicates a custom implementation
  enabled              = true
  default_from_address = "accounts@example.com"
  credentials {}
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `credentials` (Block List, Min: 1, Max: 1) Configuration settings for the credentials for the email provider. (see [below for nested schema](#nestedblock--credentials))
- `default_from_address` (String) Email address to use as the sender when no other "from" address is specified.
- `name` (String) Name of the email provider. Options include `azure_cs`, `custom`, `mailgun`, `mandrill`, `ms365`, `sendgrid`, `ses`, `smtp` and `sparkpost`.

### Optional

- `enabled` (Boolean) Indicates whether the email provider is enabled.
- `settings` (Block List, Max: 1) Specific email provider settings. (see [below for nested schema](#nestedblock--settings))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedblock--credentials"></a>
### Nested Schema for `credentials`

Optional:

- `access_key_id` (String, Sensitive) AWS Access Key ID. Used only for AWS.
- `api_key` (String, Sensitive) API Key for your email service. Will always be encrypted in our database.
- `azure_cs_connection_string` (String, Sensitive) Azure Communication Services Connection String.
- `domain` (String) Domain name.
- `ms365_client_id` (String, Sensitive) Microsoft 365 Client ID.
- `ms365_client_secret` (String, Sensitive) Microsoft 365 Client Secret.
- `ms365_tenant_id` (String, Sensitive) Microsoft 365 Tenant ID.
- `region` (String) Default region. Used only for AWS, Mailgun, and SparkPost.
- `secret_access_key` (String, Sensitive) AWS Secret Key. Will always be encrypted in our database. Used only for AWS.
- `smtp_host` (String) Hostname or IP address of your SMTP server. Used only for SMTP.
- `smtp_pass` (String, Sensitive) SMTP password. Used only for SMTP.
- `smtp_port` (Number) Port used by your SMTP server. Please avoid using port 25 if possible because many providers have limitations on this port. Used only for SMTP.
- `smtp_user` (String) SMTP username. Used only for SMTP.


<a id="nestedblock--settings"></a>
### Nested Schema for `settings`

Optional:

- `headers` (Block List, Max: 1) Headers settings for the `smtp` email provider. (see [below for nested schema](#nestedblock--settings--headers))
- `message` (Block List, Max: 1) Message settings for the `mandrill` or `ses` email provider. (see [below for nested schema](#nestedblock--settings--message))

<a id="nestedblock--settings--headers"></a>
### Nested Schema for `settings.headers`

Optional:

- `x_mc_view_content_link` (String) Disable or enable the default View Content Link for sensitive emails.
- `x_ses_configuration_set` (String) SES Configuration set to include when sending emails.


<a id="nestedblock--settings--message"></a>
### Nested Schema for `settings.message`

Optional:

- `configuration_set_name` (String) Setting for the `ses` email provider. The name of the configuration set to apply to the sent emails.
- `view_content_link` (Boolean) Setting for the `mandrill` email provider. Set to `true` to see the content of individual emails sent to users.

## Import

Import is supported using the following syntax:

```shell
# As this is not a resource identifiable by an ID within the Auth0 Management API,
# email can be imported using a random string.
#
# We recommend [Version 4 UUID](https://www.uuidgenerator.net/version4)
#
# Example:
terraform import auth0_email_provider.my_email_provider "b4213dc2-2eed-42c3-9516-c6131a9ce0b0"
```
