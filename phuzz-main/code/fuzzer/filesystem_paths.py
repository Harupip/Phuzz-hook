"""Windows filesystem paths, kept separate from persisted paths and Docker slugs."""

import os
import tempfile
from pathlib import Path


def filesystem_path(path: str | Path) -> Path:
    if os.name != "nt":
        return Path(path)
    absolute = os.path.abspath(path)
    if absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)


def check_directory_io(path: Path) -> None:
    """Fail before starting workers if the actual output directory is unusable."""
    operation = "mkdir"
    try:
        root = filesystem_path(path)
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="hp-io-", dir=root) as temporary:
            source = Path(temporary) / "check.tmp"
            destination = Path(temporary) / "check.json"
            operation = "write"
            source.write_text("filesystem check", encoding="utf-8")
            operation = "replace"
            source.replace(destination)
            operation = "read"
            if destination.read_text(encoding="utf-8") != "filesystem check":
                raise OSError("filesystem check content mismatch")
            operation = "unlink"
            destination.unlink()
    except OSError as exc:
        raise OSError(
            f"FILESYSTEM_PATH_UNSUPPORTED operation={operation} "
            f"path_length={len(os.path.abspath(path))} path={path}: {exc}"
        ) from exc
