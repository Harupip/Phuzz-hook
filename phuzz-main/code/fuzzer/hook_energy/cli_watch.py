import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from energy import EnergyScheduler


def _tier_totals(items: list[dict]) -> tuple[int, int]:
    historical_total = sum(int(item.get("previous_executed_count", 0)) for item in items)
    request_total = sum(int(item.get("request_executed_count", 0)) for item in items)
    return historical_total, request_total


def _format_component_line(component: dict) -> str:
    hook_name = component.get("hook_name", "unknown_hook")
    callback_repr = component.get("callback_repr", "unknown_callback")
    fired_hook = component.get("fired_hook", hook_name)
    previous_executed_count = int(component.get("previous_executed_count", 0))
    request_executed_count = int(component.get("request_executed_count", 0))
    energy = int(component.get("energy", 0))
    return (
        f"      - hook={hook_name} | fired_by={fired_hook} | callback={callback_repr} | "
        f"hist={previous_executed_count} | req={request_executed_count} | score=+{energy}"
    )


def _print_tier_summary(result) -> None:
    tier_labels = (
        ("first_seen", "First Seen"),
        ("rare", "Rare"),
        ("frequent", "Frequent"),
    )
    for tier_name, tier_label in tier_labels:
        items = result.components.get(tier_name, [])
        historical_total, request_total = _tier_totals(items)
        print(
            f"   => {tier_label}: {len(items)} callbacks | "
            f"historical_calls={historical_total} | request_calls={request_total}"
        )
        for component in items:
            print(_format_component_line(component))


def main():
    file_path = Path(__file__).resolve()
    repo_output_dir = file_path.parents[3] / "output"
    legacy_output_dir = file_path.parents[2] / "output"
    base_dir = Path(os.environ.get(
        "FUZZER_OUTPUT_DIR",
        str(repo_output_dir if repo_output_dir.exists() or not legacy_output_dir.exists() else legacy_output_dir),
    ))
    requests_dir = base_dir / "requests"
    snapshot_path = base_dir / "energy_state.json"

    print("=== BAT DAU THEO DOI NANG LUONG (ENERGY SCHEDULER) ===")
    print(f"Thu muc theo doi : {requests_dir}")
    print(f"File tong hop    : {snapshot_path}")
    print("-" * 50)

    scheduler = EnergyScheduler(
        requests_dir=str(requests_dir),
        snapshot_path=str(snapshot_path),
        snapshot_interval=5,
        enrich_request_files=False,
    )

    if scheduler.load_previous_state():
        stats = scheduler.calculator.get_stats()
        print(
            f"Da load state cu: {stats['total_registered']} dang ky, "
            f"{stats['total_executed']} thuc thi."
        )

    print("\n[DANG CHO REQUESTS...] Hay mo trinh duyet va tuong tac voi trang web!")

    try:
        while True:
            new_results = scheduler.process_new_requests()
            for req_id, result in new_results:
                print(f"\n[New Request] ID: {req_id}")
                print(f"   => Energy Score : {result.score} (Tier: {result.dominant_tier})")
                print(
                    f"   => Hooks: First Seen={result.first_seen_count} | "
                    f"Rare={result.rare_count} | Frequent={result.frequent_count}"
                )
                _print_tier_summary(result)

                if result.blindspot_hits > 0:
                    print(f"   => BONUS blindspot: {result.blindspot_hits}")
                if result.new_hooks_discovered > 0:
                    print(f"   => BONUS new hooks: {result.new_hooks_discovered}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDang luu state va thoat...")
        scheduler.save_state()
        print("Tam biet!")


if __name__ == "__main__":
    main()
