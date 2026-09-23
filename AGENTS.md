# Instructions for agents in this repository

## Keep the plugin config checklist current

After creating or fixing a plugin config and completing the checks required for that config, update `/plugin-test-checklist.md` in the **same task**, before reporting completion. Do this automatically; do not wait for the user to request a checklist update.

- Use one row per config path. Record the plugin, endpoint/hook, exact config path, completion date, what was completed, checks and evidence, and current verdict. Update the existing row when work continues on that config; preserve dated evidence in the row.
- Mark **Config xong** only when the config file exists and the scoped validation has passed. If work is incomplete, record `PARTIAL` or `BLOCKED` with the missing step; do not mark it complete.
- Mark **Người dùng đã test** only after the user explicitly reports a test result. Include the result and date; agent-run tests belong in the evidence column.
- Keep config generation, runtime evidence, replay/Pass 2, and fuzzing results distinct. A generated config, HTTP 200, or callback registration alone is not a runtime or fuzzing PASS.
- When a task completes no config, do not add a completion row. Do not alter unrelated checklist rows.
