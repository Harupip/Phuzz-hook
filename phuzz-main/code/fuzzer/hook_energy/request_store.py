from __future__ import annotations

import json
import logging
import os
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


def read_request_file(filepath: str) -> Optional[dict]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read request file %s: %s", filepath, exc)
        return None


def write_request_file(filepath: str, payload: dict) -> bool:
    tmp = filepath + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, filepath)
        return True
    except OSError as exc:
        logger.warning("Failed to write request file %s: %s", filepath, exc)
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                logger.warning("Failed to remove temp request file %s", tmp)
        return False


def find_new_request_files(requests_dir: str, processed_ids: Set[str]) -> List[str]:
    if not os.path.isdir(requests_dir):
        return []

    new_files = []
    for filename in os.listdir(requests_dir):
        if not filename.endswith(".json"):
            continue
        req_id = filename[:-5]
        if req_id in processed_ids:
            continue
        new_files.append(os.path.join(requests_dir, filename))
    return sorted(new_files)
