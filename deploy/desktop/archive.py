#!/usr/bin/env python3
"""Archive an already sealed/signed application and record its final file hashes."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("desktop_build", HERE / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
bootstrap = build.bootstrap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True, help="Mac .app or complete Windows/Linux application directory")
    parser.add_argument("--output", type=Path, required=True, help="new empty directory; old receipts are never overwritten")
    parser.add_argument("--signing-label", choices=("unsigned", "ad-hoc", "developer-id"), default="unsigned")
    parser.add_argument("--native-receipt", type=Path)
    args = parser.parse_args()
    app = args.app.resolve(strict=True)
    output = args.output.absolute()
    if output.is_symlink() or output.resolve().is_relative_to(app):
        parser.error("Archive output must be a separate directory outside the application")
    resources = app / ("Contents/Resources/buddy" if app.suffix == ".app" else "resources/buddy")
    manifest = json.loads((resources / "desktop-manifest.json").read_text())
    if bootstrap.records(resources) != manifest["files"] or bootstrap.runtime_identity(manifest) != manifest["runtimeId"]:
        parser.error("Resource bytes/links changed after sealing")
    if output.exists() and any(output.iterdir()):
        parser.error("Output directory must be absent or empty")
    if args.signing_label != "unsigned":
        if manifest["target"] != "macos-arm64" or sys.platform != "darwin":
            parser.error("Native signing labels require verifying the Mac application on macOS")
        checked = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], capture_output=True)
        if checked.returncode:
            parser.error("Final application signature verification failed")
    output.mkdir(parents=True, exist_ok=True)
    files = {"sourceCommit": manifest["sourceCommit"], "runtimeId": manifest["runtimeId"], "files": bootstrap.records(app)}
    build.write_json(output / "artifact-files.json", files)
    artifact = output / f"Password-Buddy-{manifest['desktopVersion']}-{manifest['target']}.zip"
    build.zip_tree(app, artifact)
    receipt = {"schemaVersion": 1, "target": manifest["target"], "sourceCommit": manifest["sourceCommit"],
               "runtimeId": manifest["runtimeId"], "appDirectory": str(app), "resources": str(resources),
               "artifact": str(artifact), "artifactBytes": artifact.stat().st_size,
               "artifactSha256": bootstrap.digest(artifact), "appFilesSha256": bootstrap.digest(output / "artifact-files.json"),
               "manifestSha256": bootstrap.digest(resources / "desktop-manifest.json"),
               "signed": args.signing_label != "unsigned", "signingLabel": args.signing_label,
               "nativeAcceptance": "native Windows unverified" if manifest["target"] == "windows-x86_64" else "not-run"}
    if args.native_receipt:
        receipt.update(nativeAcceptance="see-native-receipt", nativeReceiptName=args.native_receipt.name,
                       nativeReceiptSha256=bootstrap.digest(args.native_receipt))
    build.write_json(output / "artifact-receipt.json", receipt)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
