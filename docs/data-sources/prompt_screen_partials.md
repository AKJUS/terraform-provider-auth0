---
page_title: "Data Source: auth0_prompt_screen_partials"
description: |-
  Data source to retrieve a specific Auth0 prompt screen partials by prompt_type.
---

# Data Source: auth0_prompt_screen_partials

Data source to retrieve a specific Auth0 prompt screen partials by `prompt_type`.

## Example Usage

```terraform
data "auth0_prompt_screen_partials" "prompt_screen_partials" {
  prompt_type = "prompt-name"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `prompt_type` (String) The type of prompt to customize.

### Read-Only

- `id` (String) The ID of this resource.
- `screen_partials` (Block List) The screen partials associated with the prompt type. (see [below for nested schema](#nestedblock--screen_partials))

<a id="nestedblock--screen_partials"></a>
### Nested Schema for `screen_partials`

Read-Only:

- `insertion_points` (List of Object) (see [below for nested schema](#nestedatt--screen_partials--insertion_points))
- `screen_name` (String) The name of the screen associated with the partials

<a id="nestedatt--screen_partials--insertion_points"></a>
### Nested Schema for `screen_partials.insertion_points`

Read-Only:

- `form_content_end` (String)
- `form_content_start` (String)
- `form_footer_end` (String)
- `form_footer_start` (String)
- `secondary_actions_end` (String)
- `secondary_actions_start` (String)

