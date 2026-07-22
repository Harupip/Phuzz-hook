# Phase 10 CF7 REST

Independent Docker lab for Contact Form 7 5.7.7 REST runtime parameter discovery. It builds its own copied Phase 9 opcode extension and pinned CF7 archive; it does not mount prior phase code or results.

Run:

```bash
HOOKPHUZZ_BUILD_CA_FILE=/secure/path/environment-root-ca.crt \
bash research/hookphuzz-opcode/phase10-cf7-rest/run.sh
```

Without a private CA, omit `HOOKPHUZZ_BUILD_CA_FILE`. Current artifacts are in `results/`; prior artifacts stay in `results/history/`. The only PASS claim is REST registration, callback reachability, `WP_REST_Request::get_param` observation, config generation, and replay validation.
