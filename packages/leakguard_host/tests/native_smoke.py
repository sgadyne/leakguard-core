"""Native host navigation/spec smoke, with all writable paths owned by request."""
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import unittest

source, work = Path(sys.argv[1]), Path(sys.argv[2])
sys.path[:0] = [str(source / "src"), str(source / "packages/leakguard_host/src")]
from leakguard_host import browse, capabilities, roots, service_spec

owned = work / "host-native"
owned.mkdir(mode=0o700)
(owned / "selected").mkdir()
(owned / "selected/a").mkdir()
page = browse(owned / "selected", root=owned / "selected", limit=1)
assert page["status"] == "available" and len(page["entries"]) == 1
spec = service_spec([sys.executable, "-m", "leakguard_host.cli", "capabilities"], owned)
assert plistlib.loads(spec["content"].encode())["EnvironmentVariables"]["LEAKGUARD_STATE_DIR"] == str(owned)
lint = subprocess.run(["/usr/bin/plutil", "-lint", "-"], input=spec["content"].encode(), capture_output=True, timeout=5)
assert lint.returncode == 0
locations = roots()
assert any(item["path"] == "/" for item in locations), "native-mount-metadata-unavailable"
suite = unittest.TestLoader().discover(str(source / "packages/leakguard_host/tests"), pattern="test_host.py")
result = unittest.TextTestRunner(verbosity=1).run(suite)
assert result.wasSuccessful()
print(json.dumps({"native_platform": capabilities()["native_platform"], "navigation": "passed",
                  "mount_metadata": "passed", "launch_agent_plist": "lint-passed",
                  "service_registration": "not-performed", "compact_tests": result.testsRun,
                  "real_share": "unverified", "windows": "unverified"}, sort_keys=True))
