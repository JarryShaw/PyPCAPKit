# -*- coding: utf-8 -*-
"""Every protocol parses and constructs through one signature (GitHub issues #2840, #3081).

The owner took the plan on #2840 that splits parsing from construction, under the
rules of #2834's ``public-signatures`` page, and on #3081 let the class call do
both again. This module pins the signature:

* :class:`InitSignatureTests` -- ``ProtocolBase.__init__`` is
  ``(file=NO_VALUE, length=None, /, *, layer=None, protocol=None, context=None,
  **fields)``, and every registered protocol takes the same, with its class's own
  keyword-only extras first;
* :class:`AnalyzeSignatureTests` -- ``analyze`` and ``Transport.analyze`` take the
  keywords of ``__init__``, as a wrapper mirrors what it wraps.

This module is unit tier: it reads signatures and parses nothing.

"""
from __future__ import annotations

import inspect
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises signature machinery, which differs by interpreter.
__tier__ = 'ALL'

#: A parameter with no default.
REQUIRED = inspect.Parameter.empty

#: The keyword-only parameters each ``__init__`` override declares before the stops
#: and the context, by the class defining it, with their defaults.
EXTRAS = {
    'ProtocolBase': (),
    'IP': (('version', None),),
    'ICMP': (('version', None),),
    'IGMP': (('version', None),),
    'LinuxSLL': (('version', None),),
    'HTTP': (('version', None),),
    'L2TP': (('version', None),),
    'Frame': (('num', REQUIRED), ('header', REQUIRED)),
    'PCAPNG': (('num', REQUIRED), ('sct', REQUIRED), ('ctx', REQUIRED)),
    'IPv6_Ext': (('extension', False),),
    'DNS': (('framed', None),),
    'Loopback': (('byteorder', None),),
    'Netlink': (('byteorder', None),),
}

#: The keyword-only parameters every parse ends with, all defaulting to :obj:`None`.
STOPS = ('layer', 'protocol', 'context')


def _registered() -> 'list[type]':
    """Every class of ``ProtocolBase.__registry__``, its descriptors resolved."""
    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.protocols.protocol import ProtocolBase

    classes = []
    for entry in ProtocolBase.__registry__.values():
        classes.append(entry.klass if isinstance(entry, ModuleDescriptor) else entry)
    return classes


def _shape(func: 'Any') -> 'list[tuple[str, Any, Any]]':
    """Each parameter of ``func``, as its name, kind and default; ``self`` of a plain function left out."""
    params = list(inspect.signature(func).parameters.values())
    if params and params[0].name == 'self':
        params = params[1:]
    return [(param.name, param.kind, param.default) for param in params]


class InitSignatureTests(unittest.TestCase):
    """``file`` and ``length`` positional-only; the class's extras, then the stops, keyword-only."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def expected(self, owner: str) -> 'list[tuple[str, Any, Any]]':
        """The shape of the ``__init__`` the class ``owner`` defines."""
        from pcapkit.corekit.sentinels import NO_VALUE

        positional = [('file', inspect.Parameter.POSITIONAL_ONLY, NO_VALUE),
                      ('length', inspect.Parameter.POSITIONAL_ONLY, None)]
        keywords = [(name, inspect.Parameter.KEYWORD_ONLY, default)
                    for name, default in (*EXTRAS[owner], *((stop, None) for stop in STOPS))]
        return positional + keywords + [('fields', inspect.Parameter.VAR_KEYWORD, REQUIRED)]

    def test_the_base_signature(self) -> None:
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertEqual(_shape(ProtocolBase.__init__), self.expected('ProtocolBase'))

    def test_every_registered_protocol_takes_the_parse_signature(self) -> None:
        """Ending in ``**fields``, and an override's extras are the table's (#2840, decision 3)."""
        classes = _registered()
        self.assertTrue(classes)
        for cls in classes:
            owner = next(klass for klass in cls.__mro__ if '__init__' in vars(klass))
            with self.subTest(cls=cls.__name__, owner=owner.__name__):
                self.assertIn(owner.__name__, EXTRAS)
                self.assertEqual(_shape(cls.__init__), self.expected(owner.__name__))

    def test_every_override_in_the_table_exists(self) -> None:
        """A row whose class no longer overrides ``__init__`` is stale."""
        owners = {klass.__name__ for cls in _registered()
                  for klass in cls.__mro__ if '__init__' in vars(klass)}
        self.assertEqual(set(EXTRAS) - owners, set())


class AnalyzeSignatureTests(unittest.TestCase):
    """A wrapper mirrors what it wraps: ``analyze`` takes the keywords of ``__init__``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_analyze_takes_the_stops_and_the_context_alone(self) -> None:
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.protocols.transport.transport import Transport

        keywords = [(name, kind, default) for name, kind, default in _shape(ProtocolBase.__init__)
                    if kind is inspect.Parameter.KEYWORD_ONLY]
        for owner, first in ((ProtocolBase, 'proto'), (Transport, 'ports')):
            with self.subTest(owner=owner.__name__):
                self.assertEqual(_shape(owner.analyze), [
                    (first, inspect.Parameter.POSITIONAL_ONLY, REQUIRED),
                    ('payload', inspect.Parameter.POSITIONAL_ONLY, REQUIRED),
                    *keywords,
                ])

    def test_every_registered_protocol_s_analyze_takes_them(self) -> None:
        """Two positional-only arguments, then the stops and the context, and nothing else."""
        stops = [(stop, inspect.Parameter.KEYWORD_ONLY, None) for stop in STOPS]
        for cls in _registered():
            with self.subTest(cls=cls.__name__):
                shape = _shape(cls.analyze)
                self.assertEqual([kind for _, kind, _ in shape[:2]], [inspect.Parameter.POSITIONAL_ONLY] * 2)
                self.assertEqual(shape[2:], stops)


if __name__ == '__main__':
    unittest.main()
