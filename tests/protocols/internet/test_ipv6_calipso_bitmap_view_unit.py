# -*- coding: utf-8 -*-
"""Constructing a CALIPSO option leaves a caller's bitmap resizable.

GitHub issue #2807: the builder copies a bytes-like bitmap through a
:class:`memoryview`, which exports the caller's object until it is released.
CPython releases a dropped view as the expression ends; PyPy only once the
collector reaches it, so a :obj:`bytearray` bitmap raises :exc:`BufferError` on
resize. ``HeldViews`` keeps every view the builder takes alive, as PyPy's
collector does, and the test fails without the fix.

"""

import importlib
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises buffer semantics, which differ by interpreter.
__tier__ = 'ALL'

#: The protocol classes sharing the option code, by module and class name.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt.protocol', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts.protocol', 'IPv6_Opts'),
)


class HeldViews:
    """A :class:`memoryview` factory whose views stay alive until the test ends."""

    def __init__(self) -> None:
        self.views = []  # type: list[memoryview]

    def __call__(self, obj: 'bytearray') -> 'memoryview':
        view = memoryview(obj)
        self.views.append(view)
        return view

    def release(self) -> None:
        for view in self.views:
            view.release()


class TestCALIPSOBitmapView(unittest.TestCase):
    """A :obj:`bytearray` bitmap resizes after the option is built."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_bytearray_bitmap_resizes_after_make(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for mod, name in PROTOCOLS:
            module = importlib.import_module(mod)
            cls = getattr(module, name)
            with self.subTest(protocol=name):
                bitmap = bytearray(range(1, 9))
                held = HeldViews()
                self.addCleanup(held.release)
                with mock.patch.object(module, 'memoryview', held, create=True):
                    made = cls(next=59, options=[(Option.CALIPSO, dict(domain=1, level=5, bitmap=bitmap))])
                self.assertTrue(held.views)
                self.assertIn(bytes(range(1, 9)), made.data)

                bitmap.extend(b'\x00')


if __name__ == '__main__':
    unittest.main()
