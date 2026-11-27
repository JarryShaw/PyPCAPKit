# -*- coding: utf-8 -*-
""":mod:`tests._sources` never hands out a file as it read before it changed (#3148).

* **A rewrite straight after a read.** A filesystem advances a modification time in
  coarse ticks, so a same-size rewrite within one keeps the size and the time a
  cached entry was checked against. A file modified that recently is read again
  on every call and kept nowhere, as git treats a racy timestamp.
* **A rewrite that keeps the time.** One that restores the size and the
  modification time still changes the status-change time, and a replacement the
  inode, which the entry is checked against too.
* **Kept otherwise.** A file left alone since an earlier call is not read again.
* **Outside the checkout.** Nothing there is cached at all.

The files are written in a directory of their own under the checkout, named so
that no tree scan's glob matches them, as only the checkout is cached.

"""

from __future__ import annotations

import os
import pathlib
import tempfile
import time
import unittest

from tests import _sources
from tests._tiers import ROOT

#: Test tier (#1958): writes and reads text files, a question about the helper.
__tier__ = 'LATEST'

#: How many same-size rewrites :meth:`LoaderTests.test_a_same_size_rewrite_is_read_again` makes.
REWRITES = 50
#: A modification time old enough for the loader to keep the file: a minute ago.
SETTLED_NS = 60 * 10**9
#: How long to wait for a status-change time, which cannot be set, to leave the
#: loader's racy window, :data:`tests._sources.RACY_NS`.
SETTLE_SECONDS = 0.25


#: What the loader keeps, read to find this module's entries.
CACHE = _sources._CACHE  # pylint: disable=protected-access


def _source_of(_tree: 'object', source: 'str') -> 'str':
    """The source :func:`tests._sources.parsed` saw, for comparison."""
    return source


class LoaderTests(unittest.TestCase):

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.sources-loader-')
        self.addCleanup(temp.cleanup)
        self.dir = pathlib.Path(temp.name).resolve()
        self.addCleanup(self.forget)

    def forget(self) -> None:
        """Drop what the loader kept for this test's files."""
        for key in [key for key in CACHE if self.dir in key[1].parents]:
            del CACHE[key]

    def write(self, name: 'str', text: 'str', *, settled: 'bool' = False) -> 'pathlib.Path':
        path = self.dir / name
        path.write_text(text, encoding='utf-8')
        if settled:
            stamp = path.stat().st_mtime_ns - SETTLED_NS
            os.utime(path, ns=(stamp, stamp))
            time.sleep(SETTLE_SECONDS)
        return path

    def test_a_same_size_rewrite_is_read_again(self) -> None:
        path = self.dir / 'probe.txt'
        for index in range(REWRITES):
            first, second = f'a = {index % 10}  # a\n', f'b = {index % 10}  # b\n'
            with self.subTest(rewrite=index):
                self.write('probe.txt', first)
                self.assertEqual(_sources.text(path), first)
                self.assertEqual(_sources.parsed(path, _source_of), first)
                self.assertEqual([comment.string for comment in _sources.comments(path)], ['# a'])
                self.write('probe.txt', second)
                self.assertEqual(_sources.text(path), second)
                self.assertEqual(_sources.parsed(path, _source_of), second)
                self.assertEqual([comment.string for comment in _sources.comments(path)], ['# b'])

    def test_a_settled_file_is_kept_until_it_changes(self) -> None:
        """Each change settles before the read, so the stamp, not the racy rule, finds it."""
        path = self.write('probe.txt', 'a = 1\n', settled=True)
        kept = _sources.text(path)
        self.assertIs(_sources.text(path), kept)
        # The same size and the same modification time, written again: the ctime moves.
        stamp = path.stat().st_mtime_ns
        path.write_text('b = 2\n', encoding='utf-8')
        os.utime(path, ns=(stamp, stamp))
        time.sleep(SETTLE_SECONDS)
        self.assertEqual(_sources.text(path), 'b = 2\n')
        # Replaced by another file of that size and time: the inode moves too.
        other = self.write('other.txt', 'c = 3\n')
        os.utime(other, ns=(stamp, stamp))
        os.replace(other, path)
        time.sleep(SETTLE_SECONDS)
        self.assertEqual(_sources.text(path), 'c = 3\n')

    def test_nothing_outside_the_checkout_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp, 'probe.txt')
            path.write_text('a = 1\n', encoding='utf-8')
            self.assertEqual(_sources.text(path), 'a = 1\n')
            path.write_text('b = 2\n', encoding='utf-8')
            self.assertEqual(_sources.text(path), 'b = 2\n')
            resolved = path.resolve()
            self.assertEqual([key for key in CACHE if key[1] == resolved], [])


if __name__ == '__main__':
    unittest.main()
