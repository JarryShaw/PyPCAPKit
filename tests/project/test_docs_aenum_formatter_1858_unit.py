# -*- coding: utf-8 -*-
"""Pins the docs build's rendering of :mod:`aenum` classes in types.

GitHub issue #1858: ``typehints_fully_qualified`` is off and :mod:`aenum` has no
inventory, so a parameter annotated ``StdlibIntEnum | AenumIntEnum`` rendered as
``IntEnum | IntEnum``. ``format_class`` in :file:`docs/source/conf.py`, the
build's ``typehints_formatter``, names an :mod:`aenum` class ``aenum.IntEnum``,
as a literal since there is nothing to link to (#1920), and leaves the classes
of pcapkit and the standard library to the default rendering.

The tests call the formatter directly. They need Sphinx and
the pinned ``sphinx-autodoc-typehints``, which :file:`conf.py` imports, and skip
without them, but run no build.

"""

from __future__ import annotations

import enum
import typing
import unittest
from typing import TYPE_CHECKING

import aenum

from pcapkit.const.reg.linktype import LinkType
from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX, SPHINX_SKIP_REASON, load_conf

if TYPE_CHECKING:
    from typing import Any


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class AenumFormatterTests(unittest.TestCase):
    """``format_class`` qualifies :mod:`aenum` classes, and leaves these others alone."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def format(self, annotation: 'Any') -> 'Any':
        """The formatter's answer for ``annotation``."""
        return self.conf.format_class(annotation, None)

    def test_aenum_classes_are_qualified(self) -> 'None':
        """By the name the package exports, not the ``aenum._enum`` module defining them."""
        for cls in (aenum.IntEnum, aenum.StrEnum, aenum.Enum, aenum.IntFlag):
            with self.subTest(cls=cls):
                self.assertEqual(cls.__module__, 'aenum._enum')
                self.assertEqual(self.format(cls), f'``aenum.{cls.__name__}``')

    def test_union_members_render_apart(self) -> 'None':
        """``StdlibIntEnum | AenumIntEnum``, as ``dumpkit/pcap.py`` annotates ``protocol``."""
        answers = [self.format(arg) for arg in typing.get_args(typing.Union[enum.IntEnum, aenum.IntEnum])]
        self.assertEqual(answers, [None, '``aenum.IntEnum``'])

    def test_other_annotations_are_left_alone(self) -> 'None':
        """A standard library class, a pcapkit registry built on :mod:`aenum`, and non-classes."""
        for annotation in (enum.IntEnum, int, LinkType, 'IntEnum', None, typing.Optional[int],
                           list[aenum.IntEnum]):
            with self.subTest(annotation=annotation):
                self.assertIsNone(self.format(annotation))

    def test_conf_configures_it(self) -> 'None':
        """Only one formatter can be configured, and this is it."""
        self.assertIs(self.conf.typehints_formatter, self.conf.format_class)


if __name__ == '__main__':
    unittest.main()
