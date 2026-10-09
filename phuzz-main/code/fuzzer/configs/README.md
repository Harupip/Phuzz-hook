Configuration files
=====================

All endpoints to be fuzzed by PHUZZ have to have individual configuration files.

Reviewed 2026-10-09. Current [online-linked](../../docs/guides/online-linked-flow.md)
creates immutable configs under `online-linked/<plugin>/<storage-id>/versions/vN/`
and exports verified configs to `../output/online-linked/<run-id>/final-configs/`.
Manual `wordpress/*.json`, HAR and generated-config files remain usable by shared
tools; they are not additional wrapper modes.

The configuration file specifies the HTTP endpoint, HTTP request method and all parameters that should be sent to the targeted web application.
For each parameter class (headers, cookies, query params, body params), one can define which parameters should be fuzzed and which one should not be changed.
This allows for great flexibility when the web application expects certain values to be set, e.g. `submit=submit`.

```
"target": "http://web/wp-content/plugins/crm-perks-forms/templates/sample_file.php",
```
`target` specifies the URL of the fuzzed endpoint. It is crucial that the `host` part matches the internal docker network, e.g. the `http://web/` container.

```
"login": "example_login_script",
```

This specifies the optional login script from `automated_logins/` to be loaded. If no login script is used, this key can be omitted.

```
"methods": [
	"GET"
],
```

Specify which HTTP methods should be used for the requests. If multiple methods are defined, PHUZZ will generate N different initial HTTP requests.

The keys `headers`, `cookies`, `query_params` and `body_params` are dictionaries holding the following subvalues for the respective parameter class:

```
"data": [
	{
		"name": "param1",
		"value": "value1"
	},            
	{
		"name": "target",
		"seeds": [
		    "fuzz"
		]
	}
]
```

`data` specifies the parameters in the parameter class. The values can either be single one (`value1`) or multiple initial values (`seeds`). When multiple seed-values are specified, PHUZZ will generate N initial requests with each value.

```
"fixed": [
  "submit"
],
"fuzz": [
	".*"
],
"weight": 1
```
These keys can be used to define parameter names that should not be changed (`fixed`) or should be considered for fuzzing mutations (`fuzz`). By default, all parameters will be fuzzed if `fuzz` is an empty list. 
The key `weight` can be used to change the relative priority of the parameter class for the mutations.

Selectors are Python regexes matched with `re.match`, not glob patterns: `.*`
matches all names; `^id$` only matches `id`. Escape brackets for nested form
names. Fixed wins over fuzz. An empty `fuzz` list alone does **not** disable
mutation: generated replay-only configs fix every declared field. Exporter keeps
nonce names fixed even when runtime marks them fuzzable.

JSON transport uses `body_params` with a JSON Content-Type; runtime evidence's
`json_params` is not a separate bucket read by `fuzzer.py`. The header branch
checks exactly `Content-Type`, so preserve generated spelling.
Metadata carries method/auth/request provenance but cannot replace actual
request values or replay evidence.

Generated `config_type: replay_only` serves bounded discovery; `fuzzing_ready`
means eligible fuzz fields exist. The type alone is not runtime acceptance:
[final export](../online_linked/README.md) also checks readiness/replay, complete
nonempty Pass 2, identity and config hash.
