# Investigation

- `phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php`: `__uopz_register_rest_route`, `__uopz_rest_endpoint_args`, callback identity/source reflection, registry and executed-callback exports.
- `phuzz-main/code/fuzzer/hook_energy/method_resolution.py`: `normalize_http_methods`, route-method separation and fail-closed method decisions.
- `phuzz-main/code/fuzzer/hook_energy/rest_routes.py`: `materialize_rest_route` supports only bounded numeric named route parameters.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/config_exporter.py`: `build_config_for_seed_item` produces the existing PHUZZ schema.
- `phuzz-main/code/fuzzer/fuzzer.py`: `Fuzzer.load_config`, `load_request_data`, `generate_initial_candidates`, `prepare_request`, `ff_send_request`.
- `phuzz-main/code/fuzzer/candidate.py`: production `Candidate` model and request ID (`coverage_id`).
- `research/hookphuzz-opcode/phase12/scripts/phase12_schema.py`: conservative schema and seed rules; Phase 13 preserves missing runtime-only metadata.
- `research/hookphuzz-opcode/phase11-rest-method-generalization/phase11b-cf7/scripts/cf7_lifecycle.py`: scoped Compose lifecycle and atomic JSON artifact pattern.
