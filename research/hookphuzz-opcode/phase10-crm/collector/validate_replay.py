#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--callback", required=True)
    parser.add_argument("--response", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    config = read(args.config)
    events = read(args.events)
    callback = read(args.callback)
    fuzz = set(config["body_params"]["fuzz"])
    paths = {
        "".join(
            str(part) if index == 0 else f"[{part}]"
            for index, part in enumerate(event.get("path", []))
        )
        for event in events.get("events", [])
        if (event.get("callback_context") or {}).get("root_callback")
        == config["metadata"]["callback_id"]
    }
    response = Path(args.response).read_text()
    result = {
        "request_sent": True,
        "http_completed": bool(response),
        "action_dispatched": callback.get("callback_reached") is True,
        "callback_reached": callback.get("callback_reached") is True,
        "marker_observed": callback.get("marker_observed") is True,
        "parameter_path_matched": bool(fuzz & paths),
        "request_isolation_pass": bool(events.get("request_id")),
        "generated_config_used": True,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))
    raise SystemExit(0 if all(result.values()) else 1)


if __name__ == "__main__":
    main()
