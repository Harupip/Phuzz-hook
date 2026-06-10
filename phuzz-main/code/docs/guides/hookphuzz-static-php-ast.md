# HookPhuzz Static PHP AST Helper

This helper scans PHP plugin source code and writes AST-derived JSON artifacts for inspection, debugging, and future seed/config generation work.

It does not replace HookPhuzz runtime hook monitoring. UOPZ runtime coverage remains the source of truth for callbacks that WordPress actually registers or executes. Static AST output is advisory because it can miss runtime values, dynamic includes, reflection, variable variables, conditional registrations, and WordPress runtime state.

## Install

The helper keeps its Composer dependency local to the module and does not vendor dependencies into the repository.

```powershell
composer install --working-dir phuzz-main/code/fuzzer/static_analysis/php_ast
```

## Run

```powershell
php phuzz-main/code/fuzzer/static_analysis/php_ast/scan.php `
  --source C:\path\to\plugin `
  --out C:\path\to\output\ast
```

Add `--include-ast` only when full serialized AST output is needed. The default output is compact to keep artifacts smaller.

Add `--include-skipped` to include skipped directory paths in `ast_summary.json`.

## Outputs

- `ast_files.jsonl`: one JSON row per PHP file with file path, parse status, parse error if any, AST node count, and top-level node types.
- `ast_summary.json`: total scanned files, parsed files, failed files, total node count, default skip names, skipped paths when requested, and elapsed time.
- `hook_candidates.json`: static candidates for `add_action`, `add_filter`, `do_action`, and `apply_filters`.
- `input_candidates.json`: basic attacker-controlled input reads from `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, and `filter_input(...)`.
- `sink_candidates.json`: basic vulnerability-relevant function and method calls, including `$wpdb->query`, shell execution, file access, include/require, deserialization, XML loading, and redirect sinks.

Parse errors are recorded per file and do not stop the scan.

## Default Skips

The scanner skips these directory names by default:

- `vendor`
- `node_modules`
- `tests`
- `test`
- `cache`
- `.cache`
- `wp-admin`
- `wp-includes`

This keeps plugin scans focused and avoids parsing vendored dependencies or WordPress core unless a future version adds an explicit override.

## Limits

Static AST data is a helper layer only. It cannot prove that a hook is active at runtime, that a dynamic hook name resolves to a specific value, or that a sink is reachable from attacker input. Use it with runtime HookPhuzz coverage artifacts to prioritize manual analysis and future seed/config generation.
