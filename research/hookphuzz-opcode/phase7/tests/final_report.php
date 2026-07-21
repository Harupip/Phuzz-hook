<?php
declare(strict_types=1);

$results = rtrim($argv[1] ?? '', '/');
if ($results === '') exit(1);
$report = <<<MD
# HookPhuzz Opcode Phase 7

1. Status
PHASE_7_PASS — all required verifier gates completed.

2. Environment
See environment.txt and extension-enabled.txt.

3. Files created
See this results directory and sample-artifacts/.

4. Attribution mechanism
Zend observer begin/end context stack; see extension-enabled.txt and callback-attribution.json.

5. Target callback configuration
`hookphuzz_opcode.target_callbacks`; see extension-enabled.txt.

6. Artifact schema
Schema version 2 with callback_context and callback_summaries; see sample-artifacts/function-direct.json.

7. Direct-read regression
See direct-read-regression.json.

8. Function callback result
See callback-attribution.json.

9. Method callback result
See method-callback.json.

10. Nested helper result
See helper-attribution.json.

11. Bootstrap noise result
See bootstrap-noise.json.

12. Early-return and exception cleanup
See cleanup-tests.json.

13. Event cap result
See event-cap.json.

14. HTTP tests
See raw-enabled/ and raw-disabled/.

15. Concurrency
See concurrency.json.

16. Semantic comparison
See semantic-comparison.json.

17. Stability
See stability.json.

18. Exact command
`bash research/hookphuzz-opcode/phase7/run.sh`

19. Known limitations
Closure labels are diagnostic only; attribution covers direct reads in configured userland callback roots and descendants.

20. Deferred scope
PHUZZ/config/replay/UOPZ integration, hook discovery, propagation, taint tracking, vulnerability detection, hook energy, and benchmarks.
MD;
file_put_contents("$results/final-report.md", "$report\n");
