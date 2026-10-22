# -*- coding: utf-8 -*-
""":mod:`tests._workflows` parses each workflow text once, and hands out copies (#1967).

* **Once.** Loading a workflow again, or one of its jobs or step lists, parses
  nothing new; another file is one more parse.
* **Copies.** A caller that edits what it got, at any depth, leaves the next
  caller's result as the file reads.
* **The file as it is now.** A file rewritten in place, keeping its size and its
  modification time, is parsed afresh, and so is a doctored copy elsewhere.
* ``on``. The top-level trigger key reads ``'on'``, not YAML 1.1's :data:`True`.
* **Same objects.** The loader in use builds what :class:`yaml.SafeLoader`
  builds, with only that key told apart, from every workflow file.

"""

from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from tests import _workflows

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

#: The largest workflow, and one more.
BIG, OTHER = 'unit-tests.yml', 'lint.yml'


def reference(text: 'str') -> 'object':
    """``text`` as the pure-Python safe loader reads it, the ``True`` key spelt ``'on'``."""
    document = yaml.load(text, Loader=yaml.SafeLoader)  # nosec: B506 - a safe loader
    return {('on' if key is True else key): value for key, value in document.items()}


@unittest.skipIf(yaml is None, _workflows.NO_YAML)
class LoaderTestCase(unittest.TestCase):
    """Each test starts from an empty cache and counts the parses it causes."""

    def setUp(self) -> None:
        _workflows._parse.cache_clear()  # pylint: disable=protected-access
        patcher = mock.patch.object(_workflows.yaml, 'load', wraps=_workflows.yaml.load)
        self.parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(_workflows._parse.cache_clear)  # pylint: disable=protected-access

    def write(self, directory: 'str', text: 'str') -> 'pathlib.Path':
        path = pathlib.Path(directory) / 'doctored.yml'
        path.write_text(text, encoding='utf-8')
        return path


class TestParsesOnce(LoaderTestCase):

    def test_same_file_parses_once(self) -> None:
        for _ in range(3):
            _workflows.load(BIG)
        _workflows.job(BIG, 'test')
        _workflows.steps(BIG, 'test')
        self.assertEqual(self.parser.call_count, 1)

    def test_another_file_is_another_parse(self) -> None:
        _workflows.load(BIG)
        _workflows.load(OTHER)
        _workflows.load(_workflows.WORKFLOWS / BIG)
        self.assertEqual(self.parser.call_count, 2)

    def test_text_parses_once(self) -> None:
        text = (_workflows.WORKFLOWS / OTHER).read_text(encoding='utf-8')
        _workflows.loads(text)
        _workflows.load(OTHER)
        self.assertEqual(self.parser.call_count, 1)


class TestCallerOwnsItsCopy(LoaderTestCase):

    def test_top_level_edit_does_not_leak(self) -> None:
        first = _workflows.load(BIG)
        first['jobs'].clear()
        del first['on']
        again = _workflows.load(BIG)
        self.assertIn('on', again)
        self.assertIn('test', again['jobs'])

    def test_nested_edit_does_not_leak(self) -> None:
        text = (_workflows.WORKFLOWS / BIG).read_text(encoding='utf-8')
        found = _workflows.steps(BIG, 'test')
        found[0]['name'] = 'edited'
        found.clear()
        _workflows.loads(text)['jobs']['test']['strategy'].clear()
        again = _workflows.load(BIG)
        self.assertEqual(self.parser.call_count, 1)
        self.assertEqual(again, reference(text))

    def test_each_call_is_a_new_object(self) -> None:
        self.assertIsNot(_workflows.load(OTHER), _workflows.load(OTHER))


class TestReadsTheFileAsItIsNow(LoaderTestCase):

    def test_rewrite_keeping_size_and_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, 'name: aaa\non: push\njobs: {}\n')
            before = path.stat()
            self.assertEqual(_workflows.load(path)['name'], 'aaa')
            path.write_text('name: bbb\non: push\njobs: {}\n', encoding='utf-8')
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            self.assertEqual((after.st_size, after.st_mtime_ns), (before.st_size, before.st_mtime_ns))
            self.assertEqual(_workflows.load(path)['name'], 'bbb')

    def test_doctored_copy(self) -> None:
        text = (_workflows.WORKFLOWS / OTHER).read_text(encoding='utf-8')
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, text)
            self.assertEqual(_workflows.load(path), _workflows.load(OTHER))
            self.assertEqual(self.parser.call_count, 1)
            path.write_text(text + '\nenv:\n  DOCTORED: "1"\n', encoding='utf-8')
            self.assertEqual(_workflows.load(path)['env'], {'DOCTORED': '1'})
            self.assertNotIn('DOCTORED', _workflows.load(OTHER).get('env') or {})


class TestOnIsTheTriggerKey(LoaderTestCase):

    def test_every_workflow(self) -> None:
        for path in sorted(_workflows.WORKFLOWS.glob('*.yml')):
            with self.subTest(workflow=path.name):
                document = _workflows.load(path.name)
                self.assertIn('on', document)
                self.assertNotIn(True, list(document))

    def test_trigger_value_kept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, 'name: x\non:\n  push:\n    branches: [main]\njobs: {}\n')
            self.assertEqual(list(_workflows.load(path)), ['name', 'on', 'jobs'])
            self.assertEqual(_workflows.load(path)['on'], {'push': {'branches': ['main']}})


class TestSameObjectsAsSafeLoader(LoaderTestCase):

    def test_every_workflow(self) -> None:
        for path in sorted(_workflows.WORKFLOWS.glob('*.yml')):
            with self.subTest(workflow=path.name):
                self.assertEqual(_workflows.load(path.name), reference(path.read_text(encoding='utf-8')))


class TestSkipsWithoutPyYAML(unittest.TestCase):

    def test_skips(self) -> None:
        with mock.patch.object(_workflows, 'yaml', None):
            for call in (lambda: _workflows.load(BIG), lambda: _workflows.loads(''),
                         lambda: _workflows.job(BIG, 'test'), lambda: _workflows.steps(BIG, 'test')):
                with self.assertRaises(unittest.SkipTest):
                    call()


if __name__ == '__main__':
    unittest.main()
