# -*- coding: utf-8 -*-
"""HTTP's ``id()`` carries the RFC names of its versions. C.f. #2524.

:meth:`HTTP.id() <pcapkit.protocols.application.http.HTTP.id>` lists its members
alone, ``('HTTP/1', 'HTTP/2')``, as ``IP.id()`` does, and each versioned class
narrows to its own name: ``HTTP/2`` is RFC 9113's, and ``HTTP/1`` covers RFC 9112's
HTTP/1.1 with the versions before it. No ``id()`` carries ``'HTTP'``, ``'HTTPv1'``
or ``'HTTPv2'``, so those select through their registry keys alone.

A dispatched layer is its version's class, as an IGMP message's is, so each
version's name and key select only its own layer, and the family's key or class
selects either. The segments are built in memory: a TCP header to port 80, then
an HTTP/1.1 request or a nine-octet HTTP/2 ``DATA`` frame on stream 1.

"""

from __future__ import annotations

import importlib.util
import io
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A 20-octet TCP header, data offset 5, ACK set, from port 50000 to port 80.
_TCP_TO_80 = bytes.fromhex('c350005000000001000000015010ffff00000000')

#: Each payload, keyed by the ``id()`` name of the version it is.
PAYLOADS = {
    'HTTP/1': b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
    'HTTP/2': bytes.fromhex('000000000000000001'),
}

#: Each version's registry key, keyed by its ``id()`` name.
KEYS = {'HTTP/1': 'HTTPv1', 'HTTP/2': 'HTTPv2'}

#: Every HTTP selector: the family's registry key, each version's key, and each
#: version's ``id()`` name.
SELECTORS = ('HTTP', 'HTTPv1', 'HTTPv2', 'HTTP/1', 'HTTP/2')


def selects(selector: str, version: str) -> bool:
    """Whether ``selector`` reaches a layer of ``version``: the family, or that version."""
    return selector in ('HTTP', version, KEYS[version])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPIdTests(unittest.TestCase):
    """The ``id()`` tuples, and what they make the selectors reach."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def classes() -> 'tuple[Any, Any, Any]':
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import HTTPv1
        from pcapkit.protocols.application.httpv2 import HTTPv2

        return HTTP, HTTPv1, HTTPv2

    @staticmethod
    def frame(payload: bytes, **kwargs: 'Any') -> 'Any':
        """Return the TCP segment carrying ``payload`` to port 80, parsed."""
        from pcapkit.protocols.transport.tcp import TCP

        data = _TCP_TO_80 + payload
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return TCP(io.BytesIO(data), len(data), **kwargs)

    def test_id_lists_the_members_and_each_member_narrows_to_itself(self) -> None:
        HTTP, HTTPv1, HTTPv2 = self.classes()

        self.assertEqual(HTTP.id(), ('HTTP/1', 'HTTP/2'))
        self.assertEqual(HTTPv1.id(), ('HTTP/1',))
        self.assertEqual(HTTPv2.id(), ('HTTP/2',))
        self.assertEqual(HTTP.id(), HTTPv1.id() + HTTPv2.id())
        for klass in (HTTP, HTTPv1, HTTPv2):
            with self.subTest(klass=klass.__module__):
                self.assertFalse({'HTTP', 'HTTPv1', 'HTTPv2'} & set(klass.id()))

    def test_in_and_getitem_select_the_family_and_the_layers_own_version(self) -> None:
        """``in``, ``[]`` and the protochain reach a layer by the family's key or
        class and by its own version's name or key, and miss it by the other
        version's. An exact version such as ``'HTTP/1.1'`` is in no ``id()``, so
        only the protochain's alias match finds it."""
        from pcapkit.protocols import __proto__ as registry
        from pcapkit.utilities.exceptions import ProtocolNotFound

        _, HTTPv1, HTTPv2 = self.classes()
        members = {'HTTP/1': HTTPv1, 'HTTP/2': HTTPv2}
        for version, payload in PAYLOADS.items():
            frame = self.frame(payload)
            layer = frame.payload
            self.assertIs(type(layer), members[version])
            for selector in SELECTORS:
                keys = [selector, selector.lower()]
                if selector.upper() in registry:
                    keys.append(registry[selector.upper()])
                for key in keys:
                    with self.subTest(version=version, selector=key):
                        if selects(selector, version):
                            self.assertIn(key, layer)
                            self.assertIn(key, frame)
                            self.assertIn(key, frame.protochain)
                            self.assertIs(frame[key], layer)
                        else:
                            self.assertNotIn(key, layer)
                            self.assertNotIn(key, frame)
                            self.assertNotIn(key, frame.protochain)
                            with self.assertRaises(ProtocolNotFound):
                                frame[key]  # pylint: disable=pointless-statement

            with self.subTest(version=version, selector='HTTP/1.1'):
                self.assertNotIn('HTTP/1.1', frame)
                with self.assertRaises(ProtocolNotFound):
                    frame['HTTP/1.1']  # pylint: disable=pointless-statement
                self.assertIs('HTTP/1.1' in frame.protochain, version == 'HTTP/1')

    def test_string_eq_compares_the_layers_own_id(self) -> None:
        """String ``==`` is not expanded, so a layer equals its own version's
        name alone, and neither the family nor a version key."""
        HTTP, HTTPv1, HTTPv2 = self.classes()
        members = {'HTTP/1': HTTPv1, 'HTTP/2': HTTPv2}
        for version, payload in PAYLOADS.items():
            layer = self.frame(payload).payload
            for selector in SELECTORS:
                with self.subTest(version=version, selector=selector):
                    self.assertIs(layer == selector, selector == version)
            with self.subTest(version=version, selector='classes'):
                for klass in (HTTP, HTTPv1, HTTPv2):
                    self.assertIs(layer == klass, klass is members[version])

    def test_a_versioned_layer_built_directly_selects_alike(self) -> None:
        """A versioned class parsed directly is selected as a dispatched one is."""
        _, HTTPv1, HTTPv2 = self.classes()
        layers = {
            'HTTP/1': HTTPv1(io.BytesIO(PAYLOADS['HTTP/1']), len(PAYLOADS['HTTP/1'])),
            'HTTP/2': HTTPv2(io.BytesIO(PAYLOADS['HTTP/2']), len(PAYLOADS['HTTP/2'])),
        }
        for version, layer in layers.items():
            for selector in SELECTORS:
                with self.subTest(layer=version, selector=selector):
                    self.assertIs(selector in layer, selects(selector, version))
                    self.assertIs(layer == selector, selector == version)

    def test_protocol_stop_matches_the_family_and_its_own_version(self) -> None:
        """``protocol=`` stops at a layer for the family's selectors and its own
        version's, and not for the other version or an exact version, which
        ``_check_term_threshold`` compares against ``id()`` alone."""
        HTTP, HTTPv1, HTTPv2 = self.classes()
        classes = {'HTTP': HTTP, 'HTTPv1': HTTPv1, 'HTTPv2': HTTPv2}
        for version, payload in PAYLOADS.items():
            for selector in SELECTORS:
                for key in (selector, classes.get(selector)):
                    if key is None:
                        continue
                    with self.subTest(version=version, selector=key):
                        self.assertIs(self.frame(payload, protocol=key).payload._sigterm,
                                      selects(selector, version))
            with self.subTest(version=version, selector='HTTP/1.1'):
                self.assertIs(self.frame(payload, protocol='HTTP/1.1').payload._sigterm, False)


if __name__ == '__main__':
    unittest.main()
