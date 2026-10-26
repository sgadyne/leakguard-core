#!/usr/bin/env python3
"""Build the optional scan walker to an explicitly selected artifact path."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "native" / "scan_walk" / "Cargo.toml"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="destination file for the built helper")
    args = parser.parse_args(argv)
    if os.name != "posix":
        parser.error("the native helper currently supports POSIX; Python fallback remains available")
    cargo = shutil.which("cargo")
    if cargo is None:
        parser.error("cargo is required to build the optional helper; Python fallback remains available")
    built = ROOT / "native" / "scan_walk" / "target" / "release" / "leakguard-scan-walk"
    command = [cargo, "build", "--locked", "--release", "--manifest-path", str(MANIFEST)]
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        return completed.returncode
    destination = args.output.expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(built, destination)
    destination.chmod(destination.stat().st_mode | 0o111)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
