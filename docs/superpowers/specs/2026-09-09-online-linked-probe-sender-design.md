# Online-Linked Probe Sender Design

## Goal

Keep the active online-linked mutation worker running while probe requests and child replay are sent through a lightweight `docker exec` process.

## Contract

- Request construction remains the existing `Fuzzer.prepare_request()` semantics, with run ID and request ID passed explicitly to the sender; the parent fuzzing process environment is unchanged.
- The sender never constructs `Fuzzer`, writes fuzzer output, mutates queues, changes parent state/coverage, or sends parent stop signals; its HTTP request may create only the explicitly correlated probe artifacts.
- Sender waits for an exact request/Zend pair: request ID, probe/replay run ID, plugin, callback, method, auth context, and existing runtime parameter provenance. Temporary files and incomplete pairs are ignored.
- Existing verifier/admission and Pass 2 functions remain the only confirmation rules. Probe failures never update parent known parameters.
- V0 keeps its current standalone replay because no parent container exists yet.
- Child replay runs while parent is alive. Only after replay plus Pass 2 succeeds does the coordinator stop parent and start child; either failure keeps parent and blocks child start.
- Sender and handoff use one shared deadline and record `send_http`, `wait_artifacts`, `verify`, `handoff`, and total durations.

## Shape

`fuzzer.py` exposes a small one-shot sender entrypoint backed by extracted pure request preparation. `generated_config_runner.py` owns the single-process artifact wait/collection protocol. `online_linked_coordinator.py` supplies immutable config paths and explicit IDs, invokes the sender in the active container, checks parent exit/VULN_FOUND during waits, then reuses current artifact retention, verifier, admission, recovery, and terminal-state handling.

## Proof boundary

Unit/contract tests prove command and state invariants. No runtime speed or fuzzing claim is made unless a fresh runtime run with a new run ID is executed and its artifacts are retained separately.
