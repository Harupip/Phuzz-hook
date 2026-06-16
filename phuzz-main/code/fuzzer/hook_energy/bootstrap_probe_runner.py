from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:
    requests = None

BOOTSTRAP_PROBE_REPORT = "bootstrap_probe_report.json"

XMLRPC_DEMO_BODY = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>
"""


@dataclass(frozen=True)
class BootstrapProbe:
    probe_id: str
    name: str
    method: str
    path: str
    data: str | None = None
    headers: dict[str, str] | None = None


def default_probes() -> list[BootstrapProbe]:
    probe_specs = [
        ("frontend_home", "GET", "/"),
        ("admin_ajax_probe", "POST", "/wp-admin/admin-ajax.php?action=hookphuzz_probe"),
        ("admin_post_probe", "POST", "/wp-admin/admin-post.php?action=hookphuzz_probe"),
        ("rest_api_index", "GET", "/wp-json/"),
        ("rest_route_index", "GET", "/?rest_route=/"),
        ("login_lostpassword", "GET", "/wp-login.php?action=lostpassword"),
        ("wp_admin_index", "GET", "/wp-admin/index.php"),
        ("wp_admin_admin", "GET", "/wp-admin/admin.php"),
        (
            "xmlrpc_method_call",
            "POST",
            "/xmlrpc.php",
            XMLRPC_DEMO_BODY,
            {"Content-Type": "text/xml"},
        ),
        ("wp_cron", "GET", "/wp-cron.php"),
    ]

    probes: list[BootstrapProbe] = []
    for index, spec in enumerate(probe_specs, start=1):
        name, method, path = spec[:3]
        data = spec[3] if len(spec) > 3 else None
        headers = spec[4] if len(spec) > 4 else None
        probes.append(
            BootstrapProbe(
                probe_id=f"bootstrap-{index:02d}-{name}",
                name=name,
                method=method,
                path=path,
                data=data,
                headers=headers,
            )
        )
    return probes


def list_request_artifacts(hook_coverage_dir: str | Path) -> list[str]:
    requests_dir = Path(hook_coverage_dir) / "requests"
    if not requests_dir.exists():
        return []

    return [
        f"requests/{path.name}"
        for path in sorted(requests_dir.glob("*.json"))
        if path.is_file()
    ]


def run_probe(
    probe: BootstrapProbe,
    *,
    base_url: str,
    hook_coverage_dir: str | Path,
    timeout: float,
    http_client: Any = None,
) -> dict[str, Any]:
    before_artifacts = set(list_request_artifacts(hook_coverage_dir))
    url = _build_url(base_url, probe.path)
    headers = {
        "X-HookPhuzz-Probe-ID": probe.probe_id,
        "X-HookPhuzz-Probe-Name": probe.name,
        "X-Fuzzer-Covid": probe.probe_id,
    }
    if probe.headers:
        headers.update(probe.headers)

    started = time.perf_counter()
    status_code = None
    error = None
    try:
        response = _send_request(
            http_client,
            method=probe.method,
            url=url,
            headers=headers,
            timeout=timeout,
            data=probe.data,
        )
        status_code = getattr(response, "status_code", None)
    except Exception as exc:
        error = str(exc)
    duration_ms = int(round((time.perf_counter() - started) * 1000))

    after_artifacts = set(list_request_artifacts(hook_coverage_dir))
    new_artifacts = sorted(after_artifacts - before_artifacts)

    return {
        "probe_id": probe.probe_id,
        "name": probe.name,
        "method": probe.method,
        "path": probe.path,
        "url": url,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "error": error,
        "new_request_artifacts": new_artifacts,
    }


def run_bootstrap_probes(
    *,
    base_url: str,
    hook_coverage_dir: str | Path,
    timeout: float,
    sleep_between_probes: float = 0.2,
    http_client: Any = None,
    probes: list[BootstrapProbe] | None = None,
) -> dict[str, Any]:
    started_at = _utc_now()
    probe_results = []
    selected_probes = probes or default_probes()

    for index, probe in enumerate(selected_probes):
        probe_results.append(
            run_probe(
                probe,
                base_url=base_url,
                hook_coverage_dir=hook_coverage_dir,
                timeout=timeout,
                http_client=http_client,
            )
        )
        if sleep_between_probes > 0 and index < len(selected_probes) - 1:
            time.sleep(sleep_between_probes)

    successful_probes = sum(1 for probe in probe_results if probe["error"] is None)
    failed_probes = len(probe_results) - successful_probes
    artifacts_created = sum(len(probe["new_request_artifacts"]) for probe in probe_results)

    return {
        "schema_version": 1,
        "base_url": base_url.rstrip("/") or base_url,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "probe_count": len(probe_results),
        "probes": probe_results,
        "summary": {
            "successful_probes": successful_probes,
            "failed_probes": failed_probes,
            "artifacts_created": artifacts_created,
        },
    }


def write_report(report: dict[str, Any], output_dir: str | Path) -> Path:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    report_path = output_path / BOOTSTRAP_PROBE_REPORT
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report_path


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run WordPress bootstrap probes and report hook coverage artifacts.")
    parser.add_argument("--base-url", required=True, help="Base WordPress URL, for example http://localhost:8080.")
    parser.add_argument(
        "--hook-coverage-dir",
        required=True,
        help="Hook coverage directory containing a requests/ subdirectory.",
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write bootstrap_probe_report.json.")
    parser.add_argument("--timeout", type=float, required=True, help="Per-probe HTTP timeout in seconds.")
    parser.add_argument("--sleep-between-probes", type=float, default=0.2, help="Delay between probes in seconds.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    report = run_bootstrap_probes(
        base_url=args.base_url,
        hook_coverage_dir=args.hook_coverage_dir,
        timeout=args.timeout,
        sleep_between_probes=args.sleep_between_probes,
    )
    report_path = write_report(report, args.output_dir)
    print(
        "Bootstrap probe summary: "
        f"successful={report['summary']['successful_probes']} "
        f"failed={report['summary']['failed_probes']} "
        f"artifacts={report['summary']['artifacts_created']} "
        f"report={report_path}"
    )
    return 0


def _build_url(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{base}{path}"


def _send_request(http_client: Any, **kwargs):
    if http_client is None:
        if requests is None:
            raise RuntimeError("The requests package is required when no HTTP client is injected.")
        http_client = requests
    request_func = getattr(http_client, "request", http_client)
    return request_func(**kwargs)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
