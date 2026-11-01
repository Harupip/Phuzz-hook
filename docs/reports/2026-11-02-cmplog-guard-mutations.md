# CMPLOG guard mutations — 2026-11-02

Scope: changes made during the chat that inspected the Astra Widgets and Admin
Menu Editor reruns. Pre-existing callback-baseline, redirect, launcher, auth,
checklist and other working changes are outside this commit.

## Behavior

- `empty`/`!empty` on a callback-attributed, fuzzable input can propose `""`.
- `isset`/`!isset` can propose removing the key. Removal also strips the key from
  the target URL and does not crash interesting-candidate freezing.
- `BOOL_NOT` can propose `""` and `"0"` for a tracked truthy operand. `JMPZ` and
  `JMPNZ` handle the optimized conditional forms used by OPcache.
- Existing request deduplication, fixed/sensitive-field filtering and CMPLOG
  transport/value checks remain in use. Artifact request IDs must match.
- `TYPE_CHECK`/typed-null handling is deferred; no plugin config was generated
  or fixed in this task, and no config checklist completion row was added.

## Verification

Tests were written and failed before the corresponding implementation. An
OPcache-enabled test also failed against the initial BOOL_NOT-only handler,
then passed after conditional-jump support was added.

An isolated extension was built with `phpize`, `./configure
--enable-hookphuzz_opcode` and `make -j2` in `code-web-1`, under
`/tmp/hookphuzz-bool-not-20261102`. It was loaded only into test CLI processes;
the running Apache extension was not replaced. The build reported clock skew
on some runs but completed; the resulting module was exercised by real PHP
tests with OPcache both enabled and disabled.

Final scoped suite: 55 tests passed, no failures/errors/skips. Command from
`phuzz-main/code/fuzzer`, with `HOOKPHUZZ_OPCODE_TEST_CONTAINER=code-web-1` and
`HOOKPHUZZ_OPCODE_TEST_EXTENSION=/tmp/hookphuzz-bool-not-20261102/modules/hookphuzz_opcode.so`:

```text
python -B -m unittest tests.test_cmplog tests.test_cmplog_extension tests.test_opcode_id_limits tests.test_finding_artifact tests.test_candidate_sync tests.test_probe_sender tests.test_hook_energy_integration tests.test_request_auth_context.RequestAuthContextTests.test_guest_header_cannot_be_mutated_and_auth_cookies_are_removed
```

Separate real-PHP evidence is retained in `.superpowers/empty-guard-2026-11-01`,
`.superpowers/isset-guard-2026-11-01` and `.superpowers/bool-not-2026-11-02`.
The empty and omission fixtures reached new branches and observed previously
unread parameter names. BOOL_NOT trials reached both `!$x` and `$x == false`
branches through a local copy. These are fixture results, not a full WordPress
campaign, production-auth proof, or vulnerability PASS.

A read-only review found no concrete issues in the guard mutation, omission
transport, candidate freezing and final BOOL_NOT/JMPZ/JMPNZ changes.

## Other work from this chat

- Astra Widgets run `astra-widgets-20261101T111635Z`: four exports compared with
  the experiment reference; all semantic MISMATCH. The selected v7 contains
  both fuzz fields but lacks the reference's fixed nonce. Full differences are
  in `2026-11-01-astra-widgets-experiment-comparison.json` beside this report.
- Admin Menu Editor run `admin-menu-editor-20261101T154027Z`: two validated
  exports, v2 with `post_id` and v1 with `blog_id`; both MISMATCH the reference
  containing both fields. This chat did not change config merging.
- Fifty ZIPs with numbered prefixes were moved out of the local runnable
  archive and SHA-256 verified. Inventory is preserved in
  `phuzz-main/code/plugin-zip-backups/numbered-2026-11-01/manifest.json`.
  `admin-menu-editor.zip` and `ad-inserter.zip` were then copied back under
  unnumbered names and hash-verified. The runnable archive also retains
  `megamenu.zip` and `ninja-forms.zip`.
- Plugin ZIP libraries were already local/untracked; backup ZIP binaries remain
  local and are ignored. Their inventory is committed. Temporary extracted
  third-party source used for inspection is not part of the product change.

## Follow-up: TYPE_CHECK/null

The user's delayed clarification selected both BOOL_NOT and TYPE_CHECK in this
batch. Commit `b646182` contains the behavior and evidence above; the follow-up
adds null handling rather than rewriting that commit.

Only the `MAY_BE_NULL` mask is recorded by the new TYPE_CHECK handler. It follows
existing provenance through a local copy and emits a typed JSON null target.
REST JSON inputs retain their key with null; query/form inputs propose removing
the key. Typed-null replacement is rejected unless the candidate actually sends
an application/json body with a supported method. Fixed/sensitive parameters
and other type masks remain excluded by the existing checks.

Two review findings were reproduced and fixed: the literal string `"null"` must
not be confused with typed null inside the C event recorder, and typed-null
hash metadata must be encoded structurally rather than concatenated with an
injectable legacy value string. Ordinary mutation also handles a candidate
containing null without calling a string mutator on it.

Final follow-up suite: 62 tests passed with the same suite command and Docker
environment shown above. It includes real TYPE_CHECK runs with OPcache off and
on, using a minimal WP_REST_Request-shaped fixture. The test prepares JSON/query
requests through production Fuzzer code, then feeds the serialized values to
real PHP. JSON null and query omission reach separate null branches from an
initial literal `"null"` value. This is not a full WordPress HTTP campaign.

Follow-up evidence is in `.superpowers/null-guard-2026-11-02/`, including test
output, module/source hashes and before/after JSON snapshots. The isolated
module was rebuilt; the running Apache extension was not installed/replaced.
The next normal launcher run rebuilds the web image. Review found no remaining
concrete issues after the two fixes. No plugin config was generated or fixed.
