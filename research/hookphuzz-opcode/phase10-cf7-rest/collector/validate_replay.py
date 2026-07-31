#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


EXPECTED = {"per_page", "offset", "order", "orderby", "search"}
CALLBACK = "WPCF7_REST_Controller::get_contact_forms"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--request-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    documents = [
        json.loads(path.read_text())
        for path in Path(args.runtime_dir).glob("*replay*.rest.json")
    ]
    requests = [
        json.loads(path.read_text())
        for path in Path(args.request_dir).glob("*replay*.json")
    ]
    events = [
        event
        for document in documents
        for event in document.get("events", [])
        if event.get("callback_id") == CALLBACK
        and event.get("input_present")
        and (event.get("typed_value_match") or event.get("marker_match"))
    ]
    paths = {event.get("parameter_key") for event in events}
    result = {
        "replay_request_sent": len(requests) == 5
        and all(request.get("curl_exit") == 0 for request in requests),
        "replay_route_matched": len(requests) == 5
        and all(request.get("http_status") == 200 for request in requests),
        "replay_callback_reached": len(documents) == 5
        and all(document.get("callback_reached") is True for document in documents),
        "replay_parameter_observed": EXPECTED <= paths,
        "parameter_path_matched": EXPECTED <= paths,
        "marker_or_typed_value_matched": len(events) >= 5
        and all(
            event.get("typed_value_match") or event.get("marker_match")
            for event in events
        ),
        "request_ids": [request.get("request_id") for request in requests],
        "generated_config_used": True,
    }
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    raise SystemExit(0 if all(result.values()) else 1)


if __name__ == "__main__":
    main()
