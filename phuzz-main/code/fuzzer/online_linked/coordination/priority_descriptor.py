"""Verified field selection and the first worker activation's priority descriptor."""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any

from online_linked.coordination.request_matching import _request_payload_hash


def verified_fields(replay_result: Mapping[str, Any]) -> set[tuple[str, str]]:
    return {
        (str(row.get("bucket") or ""), str(row.get("name") or ""))
        for row in replay_result.get("verified_parameters") or [] if isinstance(row, Mapping)
    }


def field_covers(field: tuple[str, str], proven: tuple[str, str]) -> bool:
    # Zend proves the top-level key; the materializer may fuzz nested selectors under it.
    return field[0] == proven[0] and (field[1] == proven[1] or field[1].split("[", 1)[0] == proven[1])


def missing_verified_fields(
    verified: Iterable[tuple[str, str]], all_fields: Collection[tuple[str, str]],
) -> list[tuple[str, str]]:
    return sorted(p for p in verified if not any(field_covers(f, p) for f in all_fields))


def priority_targets(
    verified: Collection[tuple[str, str]], fuzzable: Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    return sorted(f for f in fuzzable if any(field_covers(f, p) for p in verified))


def priority_descriptor(
    *, replay_slug: str, child: Mapping[str, Any], targets: Sequence[tuple[str, str]], mode: str,
    ack: Mapping[str, Any], attempt: Mapping[str, Any], replay_result: Mapping[str, Any],
) -> dict[str, Any]:
    descriptor = {
        "replay_slug": replay_slug,
        "replay_hash": str(child.get("replay_config_hash") or ""),
        "targets": [list(target) for target in targets],
        "mode": mode,
        "allocated_energy": ack["allocated_energy"] if type(ack.get("allocated_energy")) is int else 0,
        "attempts_used": ack["attempts_used"] if type(ack.get("attempts_used")) is int else 0,
    }
    # The old worker's PHUZZ energy counts only for the very request this seed replays:
    # same request ID and the same sent input (a probe or the replay may have changed it).
    rows = (replay_result.get("runner") or {}).get("runs") or [{}]
    seed_payload = _request_payload_hash(rows[0].get("request_payload"))
    if (type(ack.get("seed_phuzz_energy")) is int and ack.get("request_id")
            and ack.get("request_id") == attempt.get("request_id")
            and seed_payload and seed_payload == child.get("discovery_payload_hash")):
        descriptor["seed_phuzz_energy"] = ack["seed_phuzz_energy"]
    return descriptor
