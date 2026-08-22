# Runtime `$_REQUEST` Parameter Discovery Spec

## Goal

Allow the Zend runtime-only discovery path to promote correlated `$_REQUEST['name']` reads into a concrete HTTP transport when the current request gives enough evidence, so generated PHUZZ configs can fuzz the parameter and Pass 2 can verify it.

## Observed failure

Run `show-all-comments-in-one-page-20260818T231456Z` reached `wp_ajax_sac_post_type_call` successfully. Zend recorded `REQUEST[post_type]`, `REQUEST[post_category]`, and `REQUEST[post_id]`, but the runtime normalizer accepts only `GET` and `POST`. The final seed therefore has `fuzzable_params=[]`, final config generation produces zero configs, and Pass 2 rejects `accepted=0,total=0`.

## Requirements

1. Keep the Zend path runtime-only. Do not re-enable `InputSignatureExtractor` or source-assisted parameter extraction.
2. Preserve existing direct `GET` and `POST` behavior exactly.
3. Resolve a direct `REQUEST` read using this precedence:
   - if the same name is present in exactly one correlated request transport, use that transport;
   - otherwise, for `GET`, use query;
   - otherwise, for `POST` with form or multipart content type, use form;
   - if transport remains ambiguous or unsupported, reject the parameter.
4. Emit the existing canonical downstream contract (`GET/query` or `POST/form`). Do not make convergence or config generation consume a new `REQUEST` location.
5. Apply the same normalization to Pass 2 observed Zend events, otherwise a generated `POST/form` expectation cannot match a raw `REQUEST` event.
6. Keep value-free evidence behavior. Never persist the observed value from Zend/UOPZ artifacts.
7. Keep security and structural gates: direct scalar keys only, helper depth `0`, positive observed count, callback/request/run correlation, and existing forbidden-name filtering.
8. Do not change auth classification, convergence termination rules, callback verification, or artifact retention policy.

## Out of scope

- Static source extraction changes.
- Generic acceptance of every `REQUEST` event.
- Changing the zero-parameter Pass 2 gate.
- Plugin-specific hardcoded parameter names or values.
