"""Focused synthetic CI against fresh installed wheels, outside the checkout."""
from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import sys

PACKAGES = {
    "leakguard_core": "src/leakguard_core",
    "leakguard_host": "packages/leakguard_host/src/leakguard_host",
    "leakguard_vault": "packages/leakguard_vault/src/leakguard_vault",
    "leakguard_buddy": "apps/buddy/src/leakguard_buddy",
    "credential_detector": "plugins/credential_detector/src/credential_detector",
    "presidio_detector": "plugins/presidio_detector/src/presidio_detector",
    "jose_recognizers": "plugins/jose_recognizers/src/jose_recognizers",
}
TESTS = (
    "tests/test_alpha_refinement.py",
    "tests/test_runtime_identity.py",
    "tests/test_runtime_session.py",
    "tests/test_native_filter_attribution.py",
    "tests/test_publication_failure.py",
    "tests/test_result_cache.py",
    "tests/test_desktop_migration.py",
    "packages/leakguard_host/tests/test_alpha_operational.py",
    "packages/leakguard_host/tests/test_ssh_progress.py",
    "packages/leakguard_host/tests/test_alpha_backfill.py",
    "packages/leakguard_host/tests/test_inventory_priority.py",
    "packages/leakguard_host/tests/test_known_availability.py",
    "packages/leakguard_host/tests/test_mounted_worker.py",
    "packages/leakguard_host/tests/test_publication_and_protected_stores.py",
    "packages/leakguard_vault/tests/test_vault.py",
    "packages/leakguard_vault/tests/test_partitions.py",
    "packages/leakguard_vault/tests/test_inventory_fairness.py",
    "apps/buddy/tests/test_categories.py",
    "apps/buddy/tests/test_beta_storage.py",
    "apps/buddy/tests/test_desktop.py",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    if Path.cwd().resolve().is_relative_to(source):
        raise RuntimeError("Run installed checks outside the source checkout")
    if not Path(os.environ.get("LEAKGUARD_GITLEAKS", "")).is_file():
        raise RuntimeError("Pinned native backend is required; do not skip native controls")
    count = 0
    for name, relative in PACKAGES.items():
        installed = Path(importlib.import_module(name).__file__).resolve().parent
        if installed.is_relative_to(source) or "site-packages" not in installed.parts:
            raise RuntimeError("Product must be installed from wheels: " + name)
        for path in (source / relative).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                if (installed / path.relative_to(source / relative)).read_bytes() != path.read_bytes():
                    raise RuntimeError("Installed product differs from source: " + str(path.relative_to(source)))
                count += 1
    print(json.dumps({"installed_packages": len(PACKAGES), "source_files_verified": count}))
    import pytest
    return pytest.main(["-q", "--import-mode=importlib", "-p", "no:cacheprovider",
                        "--junitxml=" + str(args.junit.resolve()),
                        *[str(source / path) for path in TESTS]])


if __name__ == "__main__":
    sys.exit(main())
