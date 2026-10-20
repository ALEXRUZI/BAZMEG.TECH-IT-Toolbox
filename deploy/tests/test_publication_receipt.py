"""Offline integrity tests: objects in disposable repositories, never remote calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('receipt', ROOT / 'deploy/verify-publication.py')
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


class ReceiptTests(unittest.TestCase):
    def test_exact_tree_and_drift_failures(self):
        with tempfile.TemporaryDirectory(prefix='toolbox-receipt-') as temp:
            root = Path(temp)
            def git(*args, data=None):
                return subprocess.check_output(['git', '-C', temp, *args], input=data)
            git('init', '--quiet')
            (root / 'app.js').write_text('// public fixture\n')
            files = {'app.js': {'mode': '100644', 'sha256': hashlib.sha256((root / 'app.js').read_bytes()).hexdigest()}}
            digest = hashlib.sha256((json.dumps(files, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()
            (root / '.release').mkdir()
            marker = root / '.release/publication.json'
            marker.write_text(json.dumps({'schema': 1, 'digest': digest, 'files': files},
                                         sort_keys=True, separators=(',', ':')) + '\n')
            git('add', '.')
            tree = git('write-tree').decode().strip()
            receipt.verify(root, tree)
            # Working-tree mutation cannot change committed-object verification.
            (root / 'app.js').write_text('// changed\n')
            receipt.verify(root, tree)
            for action in ('modify', 'extra', 'delete', 'mode', 'marker', 'marker-mode', 'marker-format'):
                with self.subTest(action=action):
                    git('read-tree', tree)
                    if action == 'modify':
                        git('add', 'app.js')
                    elif action == 'extra':
                        (root / 'extra').write_text('unexpected')
                        git('add', 'extra')
                    elif action == 'delete':
                        git('update-index', '--force-remove', 'app.js')
                    elif action == 'mode':
                        git('update-index', '--chmod=+x', 'app.js')
                    elif action == 'marker-mode':
                        git('update-index', '--chmod=+x', '.release/publication.json')
                    elif action == 'marker-format':
                        marker.write_text(json.dumps({'schema': 1, 'digest': digest, 'files': files}))
                        git('add', '.release/publication.json')
                    else:
                        git('update-index', '--force-remove', '.release/publication.json')
                    with self.assertRaises(ValueError):
                        receipt.verify(root, git('write-tree').decode().strip())


if __name__ == '__main__':
    unittest.main()
