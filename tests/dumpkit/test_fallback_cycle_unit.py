# -*- coding: utf-8 -*-
"""GitHub issue #1372: the fallback writer expands an object without bound.

``_append_fallback`` dumps an object no other branch recognises through its
attributes. A class among them was expanded too, through ``vars()``, which
reaches the whole type graph, again along every path to each shared node. A
frame's info object meeting the fallback -- as it does when its
:class:`~pcapkit.corekit.infoclass.Info` class comes from another import of
:mod:`pcapkit` -- carries its next layer's protocol class, and its JSON output
grew until the disk filled. A class is now written as its name, a cycle as a
marker, and an expansion past ``FALLBACK_LIMIT`` objects raises.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import json
import os
import plistlib
import tempfile
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

try:
    import resource
except ImportError:  # pragma: no cover - not POSIX
    resource = None  # type: ignore[assignment]

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Output size no case here comes near, and a cap on the file that the
#: unbounded expansion reaches within seconds.
SIZE_CAP = 16 * 1024 * 1024


class Node:
    """A plain object, which only the fallback writer can dump."""

    def __init__(self, **kwargs: 'object') -> None:
        self.__dict__.update(kwargs)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestFallbackBounded(unittest.TestCase):
    """The fallback writer terminates, and writes each object once."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)
        if resource is not None:
            # NOTE: without the fix, the class case writes without bound, so
            # cap the file size rather than let it fill the disk.
            limits = resource.getrlimit(resource.RLIMIT_FSIZE)
            cap = SIZE_CAP if limits[1] == resource.RLIM_INFINITY else min(SIZE_CAP, limits[1])
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, limits[1]))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_FSIZE, limits)

    def dump(self, kind: 'str', value: 'dict[str, object]') -> 'bytes':
        """Dump ``value`` through the customised ``dictdumper`` writer ``kind``."""
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper

        path = os.path.join(self.tmpdir.name, f'out.{kind.lower()}')
        make_dumper(getattr(dictdumper, kind))(path)(value, name='x')
        with open(path, 'rb') as file:
            return file.read()

    def test_reference_cycle_terminates(self) -> None:
        """An object reaching itself is written once, then as a marker."""
        node = Node(name='a')
        node.me = node  # type: ignore[attr-defined]
        record = json.loads(self.dump('JSON', {'node': node}))['x']
        self.assertEqual(record['node'], {'name': 'a', 'me': f'<circular reference: {__name__}.Node>'})

        record = plistlib.loads(self.dump('PLIST', {'node': node}))['x']
        self.assertEqual(record['node'], {'name': 'a', 'me': f'<circular reference: {__name__}.Node>'})

    def test_shared_object_is_expanded_each_time(self) -> None:
        """An object reached by two paths, but enclosing neither, is written in full twice."""
        shared = Node(leaf=0, more=Node(leaf=1))
        record = json.loads(self.dump('JSON', {'node': Node(left=shared, right=shared)}))['x']
        expected = {'leaf': 0, 'more': {'leaf': 1}}
        self.assertEqual(record['node'], {'left': expected, 'right': expected})

        record = plistlib.loads(self.dump('PLIST', {'node': Node(left=shared, right=shared)}))['x']
        self.assertEqual(record['node'], {'left': expected, 'right': expected})

    def test_expansion_past_the_limit_raises(self) -> None:
        """An object expanding into more than ``FALLBACK_LIMIT`` objects raises."""
        from pcapkit.dumpkit import common
        from pcapkit.utilities.exceptions import UnsupportedCall

        def chain(depth: 'int') -> 'Node':
            node = Node(leaf=0)
            for _ in range(depth):
                node = Node(left=node, right=node)
            return node

        # 2 ** 15 - 1 expansions, past the default limit
        with self.assertRaisesRegex(UnsupportedCall, 'more than 10000 objects'):
            self.dump('JSON', {'node': chain(14)})

        with mock.patch.object(common, 'FALLBACK_LIMIT', 7):
            # seven objects: within the limit
            record = json.loads(self.dump('JSON', {'node': chain(2)}))['x']
            self.assertEqual(record['node']['right']['left'], {'leaf': 0})
            with self.assertRaisesRegex(UnsupportedCall, 'more than 7 objects'):
                self.dump('JSON', {'node': chain(3)})

    def test_class_is_written_as_its_name(self) -> None:
        """A class, module or function is named, not expanded through ``vars()``."""
        from pcapkit.protocols.internet.ipv6 import IPv6

        holder = Node(next_type=IPv6, module=json, func=json.dumps, method=json.JSONEncoder.encode)
        data = self.dump('JSON', {'holder': holder})
        self.assertLess(len(data), 4096)
        self.assertEqual(json.loads(data)['x']['holder'], {
            'next_type': 'pcapkit.protocols.internet.ipv6.IPv6',
            'module': 'json',
            'func': 'json.dumps',
            'method': 'json.encoder.JSONEncoder.encode',
        })


if __name__ == '__main__':
    unittest.main()
