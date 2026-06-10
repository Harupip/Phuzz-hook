# Static Seed Generation

Static Seed Generation is a read-only pre-seeding stage for WordPress plugins. It scans plugin PHP source and emits candidate PHUZZ seeds/configs for direct HTTP entry hooks and REST routes before fuzzing starts.

This is not vulnerability detection. Sink hints are weak metadata for prioritization only.

The module complements HookPhuzz dynamic UOPZ hook monitoring. PHUZZ already included programmatic extraction ideas for WordPress AJAX endpoints; this module extends that approach into HookPhuzz as static pre-seeding for `wp_ajax_*`, `wp_ajax_nopriv_*`, `admin_post_*`, `admin_post_nopriv_*`, and `register_rest_route()`.

Static results must be validated against runtime artifacts before being used as research evidence:

```powershell
python -m hook_energy.static_seed_generation.cli validate --static-report static_seed_report.json --hook-report hook_gap_report.json --output static_seed_validation.json
```

Scan example:

```powershell
python -m hook_energy.static_seed_generation.cli scan --plugin-path /path/to/plugin --plugin-slug gamipress --output-dir /path/to/out --base-url http://web --include-rest --include-unresolved --write-configs
```

Limitations: dynamic hook names, callbacks through helper abstractions, complex OOP dispatchers, conditional includes, plugin settings, and deeply dynamic REST argument builders may need manual review or runtime confirmation.
