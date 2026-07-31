#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


SEEDS = {
    "per_page": 7,
    "offset": 3,
    "order": "asc",
    "orderby": "id",
    "search": "hookphuzz-search-seed",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--normalized", required=True)
    parser.add_argument("--resolution", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    normalized = json.loads(Path(args.normalized).read_text())
    resolution = json.loads(Path(args.resolution).read_text())
    names = [item["name"] for item in normalized["parameters"]]

    if names != list(SEEDS) or not all(
        item["runtime_observed"] for item in normalized["parameters"]
    ):
        raise SystemExit("only all runtime-confirmed params may generate config")

    fallback = resolution["effective_mode"] == "fallback"
    data = []
    fixed = []
    if fallback:
        data.append(
            {
                "name": "rest_route",
                "value": "/contact-form-7/v1/contact-forms",
            }
        )
        fixed.append("rest_route")
    data += [{"name": name, "value": value} for name, value in SEEDS.items()]

    config = {
        "target": (
            "http://web/"
            if fallback
            else "http://web/wp-json/contact-form-7/v1/contact-forms"
        ),
        "methods": ["GET"],
        "entrypoint_type": "rest_route",
        "query_params": {
            "data": data,
            "fixed": fixed,
            "fuzz": names,
            "weight": 1,
        },
        "cookies": {
            "data": [
                {
                    "name": "runtime_session",
                    "value": "${PHASE10_RUNTIME_SESSION}",
                }
            ],
            "fixed": ["runtime_session"],
            "fuzz": [],
            "weight": 0,
        },
        "metadata": {
            "plugin": normalized["plugin"],
            "callback_id": normalized["callback"]["id"],
            "route": "/contact-form-7/v1/contact-forms",
            "route_provenance": resolution,
            "discovery_provenance": "normalized-params.json",
            "runtime_secret_refs": ["PHASE10_RUNTIME_SESSION"],
            "seed_types": {
                "per_page": "integer",
                "offset": "integer",
                "order": "enum",
                "orderby": "enum",
                "search": "string",
            },
        },
    }
    Path(args.out).write_text(json.dumps(config, indent=2) + "\n")


if __name__ == "__main__":
    main()
