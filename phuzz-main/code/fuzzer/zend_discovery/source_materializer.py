from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath


def materialize_plugin_source(plugin_zip: Path, plugin_slug: str, destination: Path) -> Path:
    root = destination / plugin_slug
    with zipfile.ZipFile(plugin_zip) as archive:
        members = archive.infolist()
        for member in members:
            member_path = PurePosixPath(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError("PLUGIN_ZIP_UNSAFE_MEMBER")
        for member in members:
            member_path = PurePosixPath(member.filename)
            if member_path.parts and member_path.parts[0] == plugin_slug:
                archive.extract(member, destination)
    return root
