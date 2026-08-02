#!/usr/bin/env python3
"""Shared bounded lifecycle for the local Phase 11B/12 CF7 Docker stack."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


CF7_VERSION = "5.7.7"
BASE_IMAGE = "hookphuzz-phase11-rest-method:local"
CF7_IMAGE = "hookphuzz-phase11b-cf7:local"


class LifecycleError(RuntimeError):
    """A safe, actionable lifecycle failure."""


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def redact(value: str) -> str:
    return re.sub(r"(?i)(password|pwd|nonce|cookie)=\S+", r"\1=<redacted>", value)


def command(command: list[str], *, cwd: Path, timeout: int, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)
    if check and completed.returncode != 0:
        detail = redact((completed.stderr or completed.stdout).strip())
        raise LifecycleError(f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}")
    return completed


def project_name(run_id: str, owner: str) -> str:
    suffix = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    prefix = re.sub(r"[^a-z0-9]+", "-", owner.lower()).strip("-")
    return f"hookphuzz-{prefix}-{suffix}"[:63].rstrip("-")


def resolve_paths(phase_dir: Path, results_dir: Path, run_id: str, project: str, caller: str) -> dict[str, Path | str]:
    phase = phase_dir.resolve()
    results = results_dir.resolve()
    git = command(["git", "-C", str(phase), "rev-parse", "--show-toplevel"], cwd=phase, timeout=30)
    root = Path(git.stdout.strip()).resolve()
    dockerfile = phase / "Dockerfile"
    compose = phase / "docker-compose.yml"
    required = (root / "research", root / "phuzz-main", dockerfile, compose)
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise LifecycleError(f"invalid repository root {root}; missing: {', '.join(missing)}")
    value: dict[str, Path | str] = {"phase_dir": phase, "results_dir": results, "repo_root": root, "dockerfile": dockerfile, "compose_file": compose, "project": project}
    write_json(results / "path-resolution.json", {
        "schema_version": 1, "run_id": run_id, "caller": caller,
        "repository_root": str(root), "phase_dir": str(phase), "results_dir": str(results),
        "dockerfile": str(dockerfile), "compose_file": str(compose), "compose_project": project,
    })
    return value


def compose(paths: dict[str, Path | str], *arguments: str) -> list[str]:
    return ["docker", "compose", "--project-name", str(paths["project"]), "--file", str(paths["compose_file"]), *arguments]


def copy_sources(dockerfile: Path) -> list[str]:
    sources: list[str] = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        if not line.lstrip().startswith("COPY "):
            continue
        values = shlex.split(line.strip()[5:])
        if len(values) < 2:
            raise LifecycleError(f"unsupported COPY declaration in {dockerfile}: {line}")
        sources.extend(values[:-1])
    return sources


def validate_build_context(paths: dict[str, Path | str], run_id: str, caller: str) -> None:
    root, dockerfile, results = (Path(paths[key]) for key in ("repo_root", "dockerfile", "results_dir"))
    sources = copy_sources(dockerfile)
    missing = [source for source in sources if not (root / source).is_file()]
    value = {
        "schema_version": 1, "run_id": run_id, "caller": caller, "repository_root": str(root),
        "build_context": str(root), "dockerfile": str(dockerfile), "copy_sources": sources,
        "missing_copy_sources": missing, "compose_project": paths["project"],
    }
    write_json(results / "docker-build-context.json", value)
    if missing:
        raise LifecycleError(f"invalid Docker build context {root} for {dockerfile}; missing COPY source(s): {', '.join(missing)}")


def inspect(paths: dict[str, Path | str], container_id: str) -> dict[str, Any]:
    completed = command(["docker", "inspect", container_id], cwd=Path(paths["phase_dir"]), timeout=30)
    values = json.loads(completed.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise LifecycleError("docker inspect did not return exactly one container")
    return values[0]


def service_ids(paths: dict[str, Path | str], service: str, *, running: bool) -> list[str]:
    arguments = ["ps"]
    if running:
        arguments.extend(["--status", "running"])
    else:
        arguments.append("--all")
    arguments.extend(["-q", service])
    completed = command(compose(paths, *arguments), cwd=Path(paths["phase_dir"]), timeout=30)
    return [value for value in completed.stdout.splitlines() if value.strip()]


def select_single_container(paths: dict[str, Path | str], service: str, ids: list[str], states: list[dict[str, Any]]) -> str:
    if len(ids) != 1:
        raise LifecycleError(f"expected exactly one CF7 {service} container, found {len(ids)}")
    if len(states) != 1 or states[0].get("State", {}).get("Running") is not True:
        raise LifecycleError(f"resolved CF7 {service} container is not running")
    labels = states[0].get("Config", {}).get("Labels", {}) or {}
    if labels.get("com.docker.compose.project") != paths["project"] or labels.get("com.docker.compose.service") != service:
        raise LifecycleError(f"resolved CF7 {service} container labels do not match project/service")
    return ids[0]


def selected_service(paths: dict[str, Path | str], service: str) -> tuple[str, dict[str, Any]]:
    ids = service_ids(paths, service, running=True)
    states = [inspect(paths, container_id) for container_id in ids]
    return select_single_container(paths, service, ids, states), states[0]


def diagnostics(paths: dict[str, Path | str], run_id: str, message: str) -> None:
    phase, results = Path(paths["phase_dir"]), Path(paths["results_dir"])
    ps = command(compose(paths, "ps", "--all"), cwd=phase, timeout=30, check=False)
    entries: dict[str, Any] = {"run_id": run_id, "error": message, "compose_project": paths["project"], "compose_ps": redact(ps.stdout + ps.stderr), "services": {}}
    for service in ("db", "web"):
        ids = service_ids(paths, service, running=False)
        values: list[dict[str, Any]] = []
        for container_id in ids:
            state = inspect(paths, container_id).get("State", {})
            logs = command(compose(paths, "logs", "--tail", "50", service), cwd=phase, timeout=30, check=False)
            values.append({"container_id": container_id, "state": {key: state.get(key) for key in ("Status", "Running", "OOMKilled", "ExitCode", "Error", "StartedAt", "FinishedAt", "Health")}, "logs": redact(logs.stdout + logs.stderr)})
        entries["services"][service] = values
    write_json(results / "cf7-readiness.json", {"schema_version": 1, **entries})


def preflight(paths: dict[str, Path | str], run_id: str) -> None:
    records: list[dict[str, Any]] = []
    for container_id in service_ids(paths, "web", running=False):
        container = inspect(paths, container_id)
        state = container.get("State", {})
        records.append({"container_id": container_id, "state": {key: state.get(key) for key in ("Status", "Running", "ExitCode", "OOMKilled", "Error", "StartedAt", "FinishedAt")}, "restart_count": container.get("RestartCount"), "health": (state.get("Health") or {}).get("Status")})
    reason = "CF7_CONTAINER_STALE" if records else "CF7_CONTAINER_REASON_UNKNOWN"
    if any(row["state"].get("OOMKilled") is True for row in records):
        reason = "CF7_CONTAINER_OOM_KILLED"
    write_json(Path(paths["results_dir"]) / "cf7-container-investigation.json", {"schema_version": 1, "run_id": run_id, "compose_project": paths["project"], "reason_code": reason, "containers": records, "oom_proven": reason == "CF7_CONTAINER_OOM_KILLED"})


def readiness(paths: dict[str, Path | str], run_id: str, web_id: str, db_id: str) -> None:
    checks: dict[str, Any] = {"run_id": run_id, "compose_project": paths["project"], "web_container_id": web_id, "db_container_id": db_id, "checks": {}}
    commands = {
        "database_running": None,
        "database_accepting_connections": ["exec", "-T", "db", "mariadb-admin", "ping", "-h", "localhost", "-uroot", "-proot-password", "--silent"],
        "web_running": None,
        "wordpress_http_ready": ["exec", "-T", "web", "curl", "-fsS", "-o", "/dev/null", "http://localhost/wp-login.php"],
        "wordpress_installed": ["exec", "-T", "web", "wp", "core", "is-installed", "--allow-root", "--path=/var/www/html"],
        "cf7_activated": ["exec", "-T", "web", "wp", "plugin", "is-active", "contact-form-7", "--allow-root", "--path=/var/www/html"],
        "cf7_version": ["exec", "-T", "web", "wp", "plugin", "get", "contact-form-7", "--field=version", "--allow-root", "--path=/var/www/html"],
        "php_version": ["exec", "-T", "web", "php", "-r", "echo PHP_VERSION;"],
        "uopz_loaded": ["exec", "-T", "web", "php", "-r", "echo phpversion('uopz') ?: '';"],
        "cf7_rest_route_registered": ["exec", "-T", "web", "wp", "eval", "echo isset(rest_get_server()->get_routes()['/contact-form-7/v1/contact-forms']) ? 'yes' : 'no';", "--allow-root", "--path=/var/www/html"],
    }
    for name, args in commands.items():
        if name == "database_running":
            checks["checks"][name] = {"passed": True, "output": db_id, "exit_code": 0}
            continue
        if name == "web_running":
            checks["checks"][name] = {"passed": True, "output": web_id, "exit_code": 0}
            continue
        completed = command(compose(paths, *args), cwd=Path(paths["phase_dir"]), timeout=60, check=False)
        output = completed.stdout.strip()
        expected = CF7_VERSION if name == "cf7_version" else "yes" if name == "cf7_rest_route_registered" else None
        passed = completed.returncode == 0 and (expected is None or output == expected) and (name != "uopz_loaded" or bool(output)) and (name != "php_version" or output.startswith("8.2."))
        checks["checks"][name] = {"passed": passed, "output": output, "exit_code": completed.returncode}
    write_json(Path(paths["results_dir"]) / "cf7-readiness.json", {"schema_version": 1, **checks})
    if not all(row["passed"] for row in checks["checks"].values()):
        raise LifecycleError("CF7 readiness checks failed; see cf7-readiness.json")


def start(paths: dict[str, Path | str], run_id: str, caller: str) -> None:
    preflight(paths, run_id)
    validate_build_context(paths, run_id, caller)
    phase, results = Path(paths["phase_dir"]), Path(paths["results_dir"])
    command(["docker", "image", "inspect", BASE_IMAGE], cwd=phase, timeout=30)
    build = command(["docker", "build", "--pull=false", "--progress=plain", "-t", CF7_IMAGE, "-f", str(paths["dockerfile"]), str(paths["repo_root"])], cwd=phase, timeout=300, check=False)
    (results / "docker-build.log").write_text(redact(build.stdout + build.stderr), encoding="utf-8")
    if build.returncode != 0:
        raise LifecycleError(f"Docker build failed for {paths['dockerfile']} using context {paths['repo_root']}; see docker-build.log")
    command(compose(paths, "up", "-d", "--no-build"), cwd=phase, timeout=300)
    deadline, last_error = time.monotonic() + 90, "CF7 services did not become ready"
    while time.monotonic() < deadline:
        try:
            db_id, _ = selected_service(paths, "db")
            web_id, _ = selected_service(paths, "web")
            http = command(compose(paths, "exec", "-T", "web", "curl", "-fsS", "http://localhost/wp-login.php"), cwd=phase, timeout=20, check=False)
            if http.returncode == 0:
                break
            last_error = redact(http.stderr.strip() or "WordPress HTTP endpoint not ready")
        except (LifecycleError, subprocess.SubprocessError) as error:
            last_error = str(error)
        time.sleep(1)
    else:
        diagnostics(paths, run_id, last_error)
        raise LifecycleError(last_error)
    command(compose(paths, "exec", "-T", "web", "bash", "/phase11b/scripts/setup-wordpress.sh"), cwd=phase, timeout=120)
    readiness(paths, run_id, web_id, db_id)
    write_json(results / "cf7-bootstrap.json", {"schema_version": 1, "run_id": run_id, "compose_project": paths["project"], "compose_file": str(paths["compose_file"]), "web_container_id": web_id, "db_container_id": db_id, "container_id_discovered_via": "docker compose --project-name --file ps --status running -q", "container_running": True})
    write_json(results / "environment.json", {"schema_version": 1, "run_id": run_id, "compose_project": paths["project"], "repository_root": str(paths["repo_root"]), "web_container_id": web_id, "db_container_id": db_id, "authentication_material": "not stored"})


def stop(paths: dict[str, Path | str], run_id: str) -> int:
    phase = Path(paths["phase_dir"])
    completed = command(compose(paths, "down", "--volumes", "--remove-orphans"), cwd=phase, timeout=120, check=False)
    remaining = {service: service_ids(paths, service, running=False) for service in ("db", "web")} if completed.returncode == 0 else {"unknown": ["unknown"]}
    write_json(Path(paths["results_dir"]) / "cleanup-result.json", {"schema_version": 1, "run_id": run_id, "compose_project": paths["project"], "compose_file": str(paths["compose_file"]), "command": compose(paths, "down", "--volumes", "--remove-orphans"), "exit_code": completed.returncode, "remaining_scoped_service_ids": remaining, "unrelated_containers_touched": False})
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("project-name", "preflight", "start", "stop"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--owner", default="phase11b")
    parser.add_argument("--project-name")
    parser.add_argument("--phase-dir", type=Path)
    parser.add_argument("--results-dir", type=Path)
    args = parser.parse_args()
    project = args.project_name or project_name(args.run_id, args.owner)
    if args.operation == "project-name":
        print(project)
        return 0
    if args.phase_dir is None or args.results_dir is None:
        parser.error("--phase-dir and --results-dir are required for lifecycle operations")
    paths = resolve_paths(args.phase_dir, args.results_dir, args.run_id, project, args.owner)
    if args.operation == "preflight":
        preflight(paths, args.run_id)
    elif args.operation == "start":
        start(paths, args.run_id, args.owner)
    else:
        return stop(paths, args.run_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LifecycleError, subprocess.SubprocessError, subprocess.TimeoutExpired) as error:
        print(f"CF7 lifecycle error: {error}", file=sys.stderr)
        raise SystemExit(1)
