"""Install/update a Ctrlable component into custom_components/.

Stages to a temp dir then swaps the component directory (new inodes), so even a
currently-loaded native build is replaced safely. Our components also load their
.so from an out-of-tree cache (HACS-safe loader), so this is doubly safe.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import zipfile

_LOGGER = logging.getLogger(__name__)


def installed_version(cc_dir: str, product: str) -> str | None:
    """Read the installed product's manifest version, if present."""
    mf = os.path.join(cc_dir, product, "manifest.json")
    try:
        with open(mf) as fh:
            return json.load(fh).get("version")
    except (OSError, ValueError):
        return None


def install_zip(cc_dir: str, product: str, blob: bytes) -> str:
    """Extract a component zip (root = component contents) into
    custom_components/<product> via a staged atomic swap. Returns the version."""
    dest = os.path.join(cc_dir, product)
    staging = os.path.join(cc_dir, f".{product}.staging")
    backup = os.path.join(cc_dir, f".{product}.bak")
    for p in (staging, backup):
        shutil.rmtree(p, ignore_errors=True)

    os.makedirs(staging, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        # Guard against path traversal.
        for name in zf.namelist():
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"unsafe path in zip: {name}")
        zf.extractall(staging)

    mf = os.path.join(staging, "manifest.json")
    if not os.path.isfile(mf):
        shutil.rmtree(staging, ignore_errors=True)
        raise ValueError("zip has no manifest.json at root")
    with open(mf) as fh:
        version = json.load(fh).get("version", "0")

    # Swap: move current aside, move staging in, drop the backup.
    if os.path.exists(dest):
        os.replace(dest, backup)
    try:
        os.replace(staging, dest)
    except OSError:
        if os.path.exists(backup):       # restore on failure
            os.replace(backup, dest)
        raise
    shutil.rmtree(backup, ignore_errors=True)
    _LOGGER.info("Ctrlable Store: installed %s %s", product, version)
    return version
