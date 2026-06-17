# Multi-stage Hook Discovery Metadata

This note documents TASK 5: recording parent/child hook registration metadata in the UOPZ hook registry.

## Scope

Implemented scope:

- Add metadata to registered callback records when a callback registers another hook.
- Preserve that metadata in per-request artifacts, `total_coverage.json`, `runtime_hook_registry.json`, and classifier outputs.
- Report child hook summaries in validation results when replay creates new child hooks.

Out of scope:

- Recursive seed generation for child hooks.
- PHUZZ scoring changes.
- Hook-energy scheduling changes.
- Baseline PHUZZ behavior changes.

## Runtime Metadata

Every registered callback record now carries:

- `registered_inside_callback`: `true` when registration happened while another callback was executing.
- `parent_callback`: compact metadata for the active parent callback, or `null`.
- `hook_level`: `0` for bootstrap/request registration, otherwise `parent_callback.hook_level + 1`.
- `parent_hook_name`: parent hook name, if available.
- `parent_callback_id`: parent callback id, if available.
- `parent_callback_repr`: parent callback repr, if available.
- `registration_stack_depth`: callback stack depth observed during registration.

Parent callback shape:

```json
{
  "hook_name": "wp_ajax_nopriv_hookphuzz_level1",
  "callback_id": "cb-level1",
  "stable_id": "stable-level1",
  "runtime_id": "runtime-level1",
  "callback_repr": "hookphuzz_level1",
  "function_name": "hookphuzz_level1",
  "class_name": null,
  "method_name": null,
  "source_file": "/var/www/html/wp-content/plugins/demo/plugin.php",
  "source_line": 10,
  "hook_level": 0
}
```

## Callback Stack

Runtime stack state lives in:

```php
$GLOBALS['__hookphuzz_callback_stack']
```

Stack helpers live in `code/web/instrumentation/hook_coverage/uopz_hook_wp.php`:

- `__uopz_push_callback_stack()`
- `__uopz_pop_callback_stack()`
- `__uopz_current_parent_callback_metadata()`
- `__uopz_registration_context_metadata()`

`__uopz_record_actual_callback_invocation()` pushes the current registered callback metadata, records execution, and pops in `finally`.

Because the current UOPZ instrumentation observes `call_user_func*` at function-entry time, `__uopz_current_parent_callback_metadata()` also has a targeted fallback: when the explicit stack is empty, it inspects a short backtrace and matches frames against callbacks registered on the current WordPress hook. This is only used during registration context lookup, not as the primary path.

## Example Child Record

When replaying:

```http
POST /wp-admin/admin-ajax.php?action=hookphuzz_level1
```

and `hookphuzz_level1()` registers `wp_ajax_nopriv_hookphuzz_level2`, artifacts should contain a record like:

```json
{
  "hook_name": "wp_ajax_nopriv_hookphuzz_level2",
  "callback_id": "cb-level2",
  "callback_repr": "hookphuzz_level2",
  "registered_inside_callback": true,
  "hook_level": 1,
  "parent_hook_name": "wp_ajax_nopriv_hookphuzz_level1",
  "parent_callback_id": "cb-level1",
  "parent_callback_repr": "hookphuzz_level1",
  "parent_callback": {
    "hook_name": "wp_ajax_nopriv_hookphuzz_level1",
    "callback_id": "cb-level1",
    "callback_repr": "hookphuzz_level1",
    "hook_level": 0
  }
}
```

## Python Artifact Handling

`entry_classifier.py` exposes the new metadata in candidate artifacts without changing classification rules.

`bootstrap_entry_discovery.py` already preserves callback rows during registry normalization; tests now guard that parent metadata survives request-artifact fallback into `runtime_hook_registry.json`.

`seed_validator.py` adds:

```json
{
  "observed": {
    "newly_registered_child_hooks": [
      {
        "hook_name": "wp_ajax_nopriv_hookphuzz_level2",
        "callback_id": "cb-level2",
        "hook_level": 1,
        "parent_callback_id": "cb-level1"
      }
    ]
  }
}
```

## Replay And Seed Boundary

Multi-stage metadata is discovery context, not a recursive seed engine.

- `hook_level: 0` means the callback was registered during bootstrap or request setup.
- `hook_level: 1` means the callback was registered while a level 0 callback was executing.
- `hook_level: 2` means the callback was registered while a level 1 callback was executing.

The classifier keeps these levels and parent fields on every candidate row. Classification is still decided by entrypoint rules such as `wp_ajax_*`, `admin_post_*`, `admin_action_*`, `login_form_*`, and heartbeat hooks. A child hook at level 1 or level 2 does not automatically become a runnable PHUZZ config unless it also maps to a supported direct HTTP entrypoint.

`phuzz_config_writer.py` only writes configs for `classification == "direct_http"`. Setup-required and non-entry child hooks remain audit artifacts until a later pipeline adds route-specific setup or recursive seed generation.

## Verified Real Plugin Evidence

Manual replay was verified against the real `contact-form-7` WordPress plugin with the UOPZ registry targeting `/wp-content/plugins/`.

Observed request artifacts:

- `/shared-tmpfs/hook-coverage/requests/082152_GET_index_50ae.json`
- `/shared-tmpfs/hook-coverage/requests/082153_GET_index_ad96.json`
- `/shared-tmpfs/hook-coverage/requests/082153_GET_wp-login_php_affc.json`
- `/shared-tmpfs/hook-coverage/requests/082154_POST_wp-admin_admin-ajax_php_7e02.json`
- `/shared-tmpfs/hook-coverage/requests/082154_POST_wp-admin_admin-ajax_php_8931.json`

Each artifact contained this level 2 child registration:

```json
{
  "hook_name": "wpcf7_admin_init",
  "callback_repr": "WPCF7_ConstantContact->auth_redirect",
  "hook_level": 2,
  "registered_inside_callback": true,
  "parent_hook_name": "wpcf7_init",
  "parent_callback_repr": "wpcf7_constant_contact_register_service",
  "source_file": "/var/www/html/wp-content/plugins/contact-form-7/modules/constant-contact/service.php",
  "source_line": 59
}
```

The plugin source chain is:

```text
contact-form-7/load.php:121
  add_action('plugins_loaded', 'wpcf7', 10, 0)

contact-form-7/load.php:134
  add_action('init', 'wpcf7_init', 10, 0)

contact-form-7/load.php:143
  do_action('wpcf7_init')

contact-form-7/modules/constant-contact/constant-contact.php:14
  add_action('wpcf7_init', 'wpcf7_constant_contact_register_service', 20, 0)

contact-form-7/modules/constant-contact/service.php:56
  add_action('wpcf7_admin_init', array($this, 'auth_redirect'))
```

The resulting level 2 row is classified as metadata/non-entry today because `wpcf7_admin_init` is a custom plugin hook, not a direct HTTP hook family. That is expected for TASK 5.

To re-check level 2 rows from request artifacts:

```powershell
$dir = Join-Path $env:TEMP 'hookphuzz-level2-requests'
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
New-Item -ItemType Directory -Path $dir | Out-Null
docker cp code-web-1:/shared-tmpfs/hook-coverage/requests/. $dir

Get-ChildItem $dir -Filter *.json | ForEach-Object {
  $json = Get-Content $_.FullName -Raw | ConvertFrom-Json
  $cov = if ($json.hook_coverage) { $json.hook_coverage } else { $json }
  $rows = @($cov.registered_callbacks.PSObject.Properties.Value)
  foreach ($row in $rows) {
    if (($row.hook_level -as [int]) -ge 2) {
      [pscustomobject]@{
        file = $_.Name
        hook_name = $row.hook_name
        callback_repr = $row.callback_repr
        hook_level = $row.hook_level
        parent_hook_name = $row.parent_hook_name
        parent_callback_repr = $row.parent_callback_repr
      }
    }
  }
}
```

## Tests

Added or updated tests:

- `test_entry_classifier_preserves_multistage_hook_metadata`
- `test_bootstrap_entry_discovery_preserves_parent_callback_metadata`
- `test_seed_validator_reports_new_child_hooks`
- `test_uopz_multistage_metadata_contract.py`

Focused verification commands:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer
python -m unittest discover -s tests -p "test_entry_classifier.py"
python -m unittest discover -s tests -p "test_bootstrap_entry_discovery.py"
python -m unittest discover -s tests -p "test_seed_validator.py"
python -m unittest discover -s tests -p "test_uopz_multistage_metadata_contract.py"

cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook
php -l phuzz-main\code\web\instrumentation\hook_coverage\uopz_hook_wp.php
```

Manual WordPress replay is still useful when the UOPZ runtime or plugin corpus changes. The Contact Form 7 evidence above is the current real-plugin replay proof for level 2 metadata.
