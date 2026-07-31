#!/usr/bin/env python3
import argparse
import json
import subprocess
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    fuzz = config["body_params"]["fuzz"]

    if len(fuzz) != 1:
        raise SystemExit("exactly one fuzz parameter required")

    marker = "PHASE10_CRM_" + uuid.uuid4().hex
    request_id = "phase10crm-replay-" + uuid.uuid4().hex
    subprocess.run(
        [
            "bash",
            "/workspace/wordpress/crm-request.sh",
            "replay",
            request_id,
            marker,
        ],
        check=True,
    )
    result = {
        "request_id": request_id,
        "marker": "<redacted>",
        "marker_prefix": "PHASE10_CRM_",
        "config": Path(args.config).name,
        "fuzz_parameter": fuzz[0],
    }
    Path(args.out).write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
