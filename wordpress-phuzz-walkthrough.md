# PHUZZ WordPress Walkthrough

This document explains how to run PHUZZ against a WordPress target from start to finish, using the structure of this repository and the behavior verified in the current environment.

It covers:

- prerequisites
- repository structure
- single-request WordPress fuzzing
- multi-request WordPress fuzzing
- result verification
- common pitfalls

## 1. What PHUZZ Does in This Repo

PHUZZ is a coverage-guided fuzzer for PHP web applications. In this repository it runs inside Docker containers and usually needs three main pieces:

- a database container
- a web application container
- one or more fuzzer containers

For WordPress, the target application runs in the `web` container and the plugin under test is installed into the WordPress instance during startup.

## 2. Important Repository Paths

These are the paths you will use most often:

- `code/docker-compose.yml`
  - main compose file
- `code/web/applications/wordpress/`
  - WordPress application files
- `code/web/applications/wordpress/_plugins/`
  - plugin zip files to install into WordPress
- `code/fuzzer/configs/wordpress/`
  - PHUZZ JSON request configs for WordPress targets
- `code/fuzzer/output/`
  - local output directory for copied results
- `code/hargen/`
  - HAR-to-config generator
- `code/composegen/`
  - compose generator for many fuzzers/configs

## 3. Prerequisites

Before starting, make sure you have:

- Docker Desktop running
- Docker Compose available
- enough RAM for multiple containers
- a WordPress plugin zip file if you want to fuzz a plugin-specific target

Useful checks:

```powershell
docker version
docker compose version
```

## 4. How WordPress Is Wired Here

The WordPress startup logic lives in:

- `code/web/applications/wordpress/init.sh`

This script:

1. waits for MySQL
2. creates `wp-config.php`
3. installs WordPress
4. installs the target plugin from `_plugins`
5. enables Apache and the PHUZZ proxy setup

The key environment variables are:

- `APPLICATION_TYPE=wordpress`
- `WP_TARGET_PLUGIN=<plugin-slug>`
- `FUZZER_COVERAGE_PATH=/var/www/html/wp-content/plugins/<plugin-slug>/`
- `REQUIRES_DB=1`

Important detail:

The plugin zip file must exist in:

- `code/web/applications/wordpress/_plugins/`

If the zip file is missing, WordPress may still boot, but plugin installation during a fresh setup will fail.

## 5. Single-Request WordPress Fuzzing

This is the simplest workflow and matches the live verification performed in this environment.

### Step 1: Prepare the plugin zip

Put the plugin archive into:

- `code/web/applications/wordpress/_plugins/`

Example:

- `show-all-comments-in-one-page.zip`

The plugin slug should match the value you will use in `WP_TARGET_PLUGIN`.

### Step 2: Prepare or choose a WordPress config

This repo already contains example WordPress configs in:

- `code/fuzzer/configs/wordpress/`

For example:

- `show-all-comments-in-one-page.json`

That config defines:

- target URL
- HTTP method
- fixed parameters
- fuzzable parameters
- parameter weights

In the verified example, the config fuzzes only:

- `query_params.post_type`

while keeping:

- `action=sac_post_type_call`

fixed.

### Step 3: Configure Docker for WordPress

You need the `web` container to use WordPress instead of DVWA.

At minimum, the `web` container environment should look like this:

```yaml
APPLICATION_TYPE: wordpress
WP_TARGET_PLUGIN: show-all-comments-in-one-page
FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/show-all-comments-in-one-page/
FUZZER_COMPRESS: 1
REQUIRES_DB: 1
```

And the fuzzer container should point at:

```yaml
FUZZER_CONFIG: wordpress/show-all-comments-in-one-page
FUZZER_NODE_ID: 1
FUZZER_CLEANUP: 1
FUZZER_COMPRESS: 1
```

### Step 4: Start database and WordPress

From `code/`:

```powershell
docker compose up -d db --build --force-recreate
docker compose up -d web --build --force-recreate
```

Wait until:

- MySQL reports ready for connections
- Apache is serving WordPress

Useful checks:

```powershell
docker compose logs db --tail=80
docker compose logs web --tail=120
```

### Step 5: Verify WordPress is reachable

The `web` container exposes:

- `http://localhost:8080/`
- `http://localhost:8181/`

Check both:

```powershell
Invoke-WebRequest -Uri http://localhost:8080/ -UseBasicParsing
Invoke-WebRequest -Uri http://localhost:8181/ -UseBasicParsing
```

Status `200` is a good sign.

### Step 6: Start the fuzzer

Run the matching fuzzer service:

```powershell
docker compose up fuzzer-wordpress-show-all-comments-in-one-page-1 --build --force-recreate
```

The exact service name depends on your compose file. In the verified environment, an already existing container named:

- `code-fuzzer-wordpress-show-all-comments-in-one-page-1-1`

was restarted directly.

### Step 7: Inspect results

Inside the running fuzzer container, results are typically stored under:

- `/app/output/fuzzer-1/`

Important files:

- `vulnerable-candidates.json`
- `exceptions-and-errors.json`

If the bind-mounted host directory does not update correctly, copy the files manually:

```powershell
docker cp <fuzzer-container>:/app/output/fuzzer-1/vulnerable-candidates.json code\fuzzer\output\vulnerable-candidates-wordpress.json
docker cp <fuzzer-container>:/app/output/fuzzer-1/exceptions-and-errors.json code\fuzzer\output\exceptions-and-errors-wordpress.json
```

## 6. What Is Actually Being Fuzzed

A PHUZZ config does not automatically fuzz every field.

For the verified example in this repo:

- request type: one request template
- method: `GET`
- endpoint: `/wp-admin/admin-ajax.php`
- fixed query parameter: `action=sac_post_type_call`
- fuzzed query parameter: `post_type`

So during that run PHUZZ was:

- fuzzing one request shape
- mutating one parameter repeatedly

It was not mutating all headers, cookies, query params, and body params at the same time.

## 7. Multi-Request WordPress Fuzzing

If you want to fuzz many request templates instead of one, use a HAR-based workflow.

### Step 1: Start WordPress

Bring up WordPress first as described above.

### Step 2: Capture traffic into a HAR file

Open:

- `http://localhost:8080/`

Then interact with WordPress and the plugin thoroughly in a browser. Export the captured traffic as a HAR file.

Place the HAR file into:

- `code/fuzzer/resources/`

### Step 3: Generate PHUZZ configs with HARgen

Edit the arguments in:

- `code/hargen/hargen.sh`

Then run from `code/`:

```powershell
docker compose up hargen --build --force-recreate
```

HARgen can:

- generate many JSON configs
- include or exclude URL prefixes
- include or exclude methods
- choose which headers, cookies, query params, or body params should be fuzzed

Generated configs are written into:

- `code/fuzzer/configs/`

### Step 4: Generate a compose file for many configs

Edit:

- `code/composegen/composegen.sh`

You can use either:

- `--configs "configA:4" "configB:4"`
  - explicit list of configs and instance counts
- `--config-dir`
  - generate fuzzers for every config in a directory

Then run:

```powershell
docker compose up composegen --force-recreate
```

The generated compose file is written into:

- `code/composegen/docker-compose.yml`

Then copy it into place if needed.

### Step 5: Run many fuzzers

Once the generated compose file is active, PHUZZ can run:

- many different request configs
- many parallel instances per config

That is how this repository scales from one request template to many.

## 8. WordPress Batch Fuzzing in `experiments/`

The repository also contains an example batch workflow for WordPress plugin campaigns:

- `experiments/02-0day-vulns/02-fuzz-all-plugin-configs.py`

That script does the following:

1. picks a plugin-specific compose file and config
2. copies them into `code/`
3. copies the plugin zip into `_plugins`
4. starts WordPress
5. waits for the site to become reachable
6. starts multiple fuzzers
7. lets them run for a fixed duration
8. collects output
9. removes temporary files

This is the practical pattern to follow if you want to fuzz many WordPress plugin targets in sequence.

## 9. How to Verify That PHUZZ Is Really Running

Do not trust the existence of a result file alone. Verify actively.

### Check container state

```powershell
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Check web logs

```powershell
docker logs <web-container> --tail 120
```

You should see repeated requests with changing fuzz values, for example:

- `post_type=fAzz`
- `post_type=fuzzV`
- `post_type=fuz%27`
- `post_type=<script>...`

If the parameter value changes across requests, PHUZZ is mutating input rather than replaying the same request.

### Check fuzzer logs

```powershell
docker logs <fuzzer-container> --tail 160
```

Look for messages such as:

- `Vulnerable candidates saved!`
- `Exceptions and errors candidates saved!`
- `Found WebFuzzXSSVulnCheck!`

### Check the output directory inside the container

```powershell
docker exec <fuzzer-container> ls -R /app/output
```

## 10. How to Interpret Findings Carefully

A PHUZZ finding means the fuzzer observed behavior that matched one of its vulnerability checks.

That does not always mean the issue is fully exploitable in a browser.

For example, in the verified WordPress case:

- PHUZZ correctly found unsanitized reflection of `post_type`
- the response included injected HTML
- the browser DOM contained an injected `img` node
- but JavaScript execution was not proven automatically

So treat results in layers:

1. PHUZZ is running
2. the request was mutated
3. the response reflected the payload
4. browser execution still needs manual confirmation when relevant

## 11. Common Pitfalls

### Missing plugin zip

If `_plugins/<slug>.zip` is missing, fresh plugin installation will fail.

### Compose file still points to DVWA

The default `code/docker-compose.yml` in this repo may still point to:

- `APPLICATION_TYPE: dvwa`
- `FUZZER_CONFIG: dvwa/...`

You must switch it to WordPress or use a generated compose file.

### Output not visible on the host

Sometimes results appear inside the container but do not show up immediately in the host `code/fuzzer/output/` directory. In that case, use `docker cp`.

### False confidence from one request

If you fuzz only one request template, you are exploring only one small part of the plugin surface.

To broaden coverage:

- capture more traffic
- generate more configs
- run more fuzzers

## 12. Recommended End-to-End Workflow

For a realistic WordPress fuzzing campaign in this repo, use this order:

1. prepare the plugin zip
2. boot WordPress and verify it works
3. capture realistic plugin traffic into HAR
4. generate many configs with HARgen
5. use Composegen to create many fuzzer services
6. run multiple instances per config
7. collect results
8. manually verify the most interesting findings

## 13. Minimal Command Checklist

From `code/`:

```powershell
docker compose up -d db --build --force-recreate
docker compose up -d web --build --force-recreate
docker compose logs web --tail 120
docker compose up <fuzzer-service> --build --force-recreate
docker logs <fuzzer-container> --tail 160
docker exec <fuzzer-container> ls -R /app/output
```

For HAR-based multi-request fuzzing:

```powershell
docker compose up hargen --build --force-recreate
docker compose up composegen --force-recreate
```

## 14. Final Notes

The most important distinction is this:

- PHUZZ can fuzz many request types
- but only if you give it many config files or many generated services

If you only provide one WordPress config, it will fuzz one request template very thoroughly.

If you provide many configs, it can scale to many plugin actions, endpoints, and request patterns.
