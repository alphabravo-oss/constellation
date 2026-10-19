import importlib.util
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('scanner_builder', ROOT/'scripts/build-scanner-tools.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ScannerBuildTests(unittest.TestCase):
    def test_source_checksum_and_module_identity_required(self):
        source = {'module': 'example.test/tool', 'version': 'v1.0.0', 'sum': 'h1:reviewed'}
        valid = {'Path': source['module'], 'Version': source['version'], 'Sum': source['sum'], 'Dir': '/source'}
        self.assertEqual(builder.source_directory(valid, source), Path('/source'))
        for key in ['Path', 'Version', 'Sum']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.source_directory({**valid, key: 'different'}, source)

    def test_source_patch_requires_exact_input_and_unique_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/'registry.go'
            original = b'old-helper'
            target.write_bytes(original)
            change = {'path': 'registry.go', 'sha256': hashlib.sha256(original).hexdigest(),
                      'replacements': {'old-helper': 'maintained-helper'}}
            builder.patch_source(root, {'patches': [change]})
            self.assertEqual(target.read_bytes(), b'maintained-helper')
            with self.assertRaisesRegex(ValueError, 'reviewed input'):
                builder.patch_source(root, {'patches': [change]})
            for path in ['../outside.go', '/outside.go']:
                with self.assertRaisesRegex(ValueError, 'inside'):
                    builder.patch_source(root, {'patches': [{**change, 'path': path}]})
            target.write_bytes(original)
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                builder.patch_source(root, {'patches': [{**change, 'replacements': {'missing': 'new'}}]})
            self.assertEqual(target.read_bytes(), original)
            target.unlink()
            outside = root/'other.go'
            outside.write_bytes(original)
            target.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'symlinks'):
                builder.patch_source(root, {'patches': [change]})
            self.assertEqual(outside.read_bytes(), original)

    def test_unpatched_compiler_rejected_before_download_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'sources.json').write_text(json.dumps({'go': 'go1.26.9', 'tools': []}))
            with patch.object(builder.subprocess, 'check_output', return_value='go1.26.8\n') as command:
                with self.assertRaisesRegex(ValueError, 'require go1.26.9'):
                    builder.build(root, root/'work', root/'output')
            self.assertEqual(command.call_count, 1)
            self.assertFalse((root/'output').exists())


if __name__ == '__main__':
    unittest.main()
