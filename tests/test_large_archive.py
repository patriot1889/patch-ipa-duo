"""Opt-in ZIP32 size regression; uses a 2.1 GB temporary resource."""
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from ipaduo.archive import write_archive


class LargeArchiveTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('IPADUO_LARGE_TESTS') == '1', 'Set IPADUO_LARGE_TESTS=1 for the 2.1 GB resource check')
    def test_large_zip32_resource_does_not_require_zip64(self):
        with tempfile.TemporaryDirectory(prefix='ipaduo-large-') as temporary:
            root = Path(temporary)
            app = root / 'source/Payload/Test.app'
            app.mkdir(parents=True)
            # Sparse on supporting filesystems; portable but may allocate space.
            with (app / 'LargeResource').open('wb') as stream:
                stream.truncate(2_100_000_000)
            output = root / 'large.ipa'
            write_archive(root / 'source', output, set())
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.getinfo('Payload/Test.app/LargeResource').file_size, 2_100_000_000)
                self.assertIsNone(archive.testzip())


if __name__ == '__main__':
    unittest.main()
