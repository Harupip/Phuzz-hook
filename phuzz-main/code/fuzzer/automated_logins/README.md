Automated Logins
====================

Automated login scripts can be configured to be called by a fuzzer to perform initial HTTP requests / actions, e.g. logging in / obtaining a valid session / configuring the web application / etc.

The trimmed WordPress-only repo does not rely on any bundled automated login script by default. While these scripts were primarily being used to prepare session cookies for the fuzzers by storing them in `"/shared-tmpfs/cookies_node{os.environ['FUZZER_NODE_ID']}.json"`, they are mostly obsolete when function hooking is used to override authentication and authorization checks.
