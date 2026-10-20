Web component
==================

This component contains the web server, server-side instrumentation and target applications.

Reviewed 2026-10-09. The [online-linked runner](../docs/guides/run-wordpress-plugins.md)
supplies a Compose override for `Dockerfile.zend`: PHP 8.2.10 plus local
`fuzzer/zend_discovery/extension/` source, built with repository-root context.
Base Compose uses `Dockerfile` and does not itself enable Zend.

UOPZ registration/execution and request evidence live under
`instrumentation/hook_coverage/`. Zend loads the registry from
`/shared/hookphuzz-callback-registry.json` and writes
`/shared/opcode-events/<request_id>.json`. Hook request artifacts use
`/shared-tmpfs/hook-coverage/requests/`. The runner mounts the shared volume at
both roots and resets runtime artifacts before a campaign.

By default, the container is built using the PHP version 8, but a PHP 7 version also exists. If you need PHP 7, change `dockerfile: Dockerfile` to `dockerfile: Dockerfile.php7` in the docker-compose.yml.

## Applications

If you want to add a fuzz target, create a new folder in the `./applications/` directory and place the files that should be copied to the containers `/var/www/html/` (DocumentRoot) in there.
Furthermore, you can create a folder named `_overrides` in the application's folder. The instrumentation will load and execute any `*.php` file that you place there, e.g. to load application-specific instrumentation/function hooks.
Additionally, you can place an `init.sh` shell script in the application's folder that will be executed upon the container's startup, e.g. to change the web server's configuration.

The checked-in repo currently ships with:

- wordpress - https://wordpress.org/ with a set of example plugin configs.

The earlier benchmark applications used in the research paper were removed from this trimmed workspace to keep the WordPress-only flow lighter.

WordPress `init.sh` prefers `<slug>.zip` in optional read-only `/plugin-zips`,
then falls back to the application's `_plugins`. Dependencies use the same
fallback: WooCommerce for `udraw`, Contact Form 7 for
`country-state-city-auto-dropdown`. CMB2's working-tree setup installs the
`_fixtures/cmb2-oembed.php` mu-plugin. Setup for other plugin prerequisites is
not automatic.

Application `_overrides` contain lab auth/capability/nonce hooks. Callback
reachability under overrides does not prove original plugin auth behavior.
LearnPress has dedicated nonce-proof setup in the runner. Missing dependencies
or data can prevent registration; inspect artifacts before extending timeouts.

## Configs

This folder contains the Apache webserver's configuration file (`mpm_prefork.conf`) and PHP configuration file (`php.ini`). The latter configures the required PHP extensions for function hooking and coverage collection.

PHUZZ supports coverage collection with PCOV and XDebug. PCOV is said to be more performant, so if you prefer to use Xdebug, you will have to set `pcov.enable=0`.

Also, Opcache is used to increase the PHP performance. If you use PHUZZ to debug an application and want to change the PHP files, set `opcache.validate_timestamps=1`.

## Instrumentation

This folder contains the PHP files that will be copied into the docker container to perform the target instrumentation. 

`__fuzzer__startcov.php` is loaded by `auto_prepend_file` in the PHP configuration, and `__fuzzer__stopcov.php` executed by `auto_append_file`. The former initializes the coverage collection and loads the function hook definitions which are in separate files in `overrides.d/`.

Instrumentation reports coverage, exceptions/errors and sink-specific signals
through shared artifacts; fuzzer checkers consume them by request/coverage ID.
See [architecture](../docs/reference/architecture.md) for admission and findings.
Check image/source parity in a fresh runtime before claiming an extension change
is active.
