import importlib.util
import json
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
