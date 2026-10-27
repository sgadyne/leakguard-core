"""Checks for resource omissions and altered wheel bytes in the release gate."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'credential_install_smoke.py'
spec = importlib.util.spec_from_file_location('credential_install_smoke', SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class WheelResourcesTest(unittest.TestCase):
    def test_resource_bytes_and_members_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            (source / 'resources').mkdir(parents=True)
            (source / '__init__.py').write_text('', encoding='utf-8')
            (source / 'resources' / 'common.json').write_text('{"schema_version":1}\n', encoding='utf-8')
            wheel = root / 'test.whl'
            def make(files):
                with zipfile.ZipFile(wheel, 'w') as z:
                    for name, value in files.items():
                        z.writestr('example/' + name, value)
            good = {'__init__.py': b'', 'resources/common.json': b'{"schema_version":1}\n'}
            required = {'resources/common.json'}
            make(good)
            result = smoke.verify_wheel(wheel, source, 'example', required)
            self.assertIn('example/resources/common.json', result)
            make({'__init__.py': b''})
            with self.assertRaisesRegex(ValueError, 'wheel-file-set-mismatch'):
                smoke.verify_wheel(wheel, source, 'example', required)
            make({**good, 'resources/common.json': b'{}'})
            with self.assertRaisesRegex(ValueError, 'wheel-source-mismatch'):
                smoke.verify_wheel(wheel, source, 'example', required)
            (source / 'resources' / 'common.json').unlink()
            with self.assertRaisesRegex(ValueError, 'source-resource-missing'):
                smoke.verify_wheel(wheel, source, 'example', required)


if __name__ == '__main__':
    unittest.main()
