#!/usr/bin/env python3
"""Reseal a Mac resource manifest after explicit native code signing.

This does not sign anything. Run before signing the outer .app. Only changes to
existing Mach-O files are accepted; original input provenance remains preserved.
"""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bootstrap", HERE / "bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
MACHO = {bytes.fromhex(value) for value in ("feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--signing-label", choices=("ad-hoc", "developer-id"), required=True)
    args = parser.parse_args()
    resources = args.resources.resolve(strict=True)
    manifest_path = resources / "desktop-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest["target"] != "macos-arm64":
        parser.error("Mac resealing requires a macos-arm64 resource manifest")
    before = {item["path"]: item for item in manifest["files"]}
    after = {item["path"]: item for item in bootstrap.records(resources)}
    if before.keys() != after.keys():
        parser.error("Payload paths changed; native signing may not add/remove resources")
    changed = []
    for relative in sorted(before):
        old, new = before[relative], after[relative]
        if old == new:
            continue
        path = resources / relative
        if old.get("linkTarget") or new.get("linkTarget") or old["mode"] != new["mode"]:
            parser.error("Native signing changed a link or file permissions")
        with path.open("rb") as stream:
            native = stream.read(4) in MACHO
        if not native or not (relative.startswith("python/") or relative.startswith("backend/LeakGuard/backends/")):
            parser.error("Changed payload is not an existing native runtime/backend file")
        changed.append({"path": relative, "originalSha256": old["sha256"], "signedSha256": new["sha256"]})
    if not changed:
        print(json.dumps({"changedNativeFiles": 0, "runtimeId": manifest["runtimeId"]}))
        return
    release_path = resources / "backend/LeakGuard/release.json"
    release = json.loads(release_path.read_text())
    for artifact in release["backend_artifacts"]:
        artifact["sha256"] = bootstrap.digest(resources / "backend/LeakGuard" / artifact["bundle_path"])
    write(release_path, release)
    provenance_path = resources / "provenance.json"
    provenance = json.loads(provenance_path.read_text())
    previous = manifest["runtimeId"]
    provenance["nativeSigning"] = {"label": args.signing_label, "previousRuntimeId": previous, "files": changed}
    write(provenance_path, provenance)
    manifest["files"] = bootstrap.records(resources)
    manifest["runtimeId"] = bootstrap.runtime_identity(manifest)
    write(manifest_path, manifest)
    print(json.dumps({"changedNativeFiles": len(changed), "previousRuntimeId": previous,
                      "runtimeId": manifest["runtimeId"], "manifestSha256": bootstrap.digest(manifest_path)}))


if __name__ == "__main__":
    main()
