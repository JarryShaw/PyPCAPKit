# -*- coding: utf-8 -*-
"""GitHub issue #2859: a pseudo-header ``verify_upper`` cannot derive is refused quietly.

With ``CHECKSUM_VERIFY`` on, an IPv4 or IPv6 layer verifies its upper layer through
:func:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.verify_upper`, which
builds the layer's :class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`.
Where it cannot -- a Routing header of a type not parsed with segments left, or a
first fragment -- the upper layer records ``NO_PSEUDO_HEADER``, and the refusal logs
nothing on the ``pcapkit`` logger and leaves :data:`sys.excepthook` and
:data:`threading.excepthook` as they were (#2588). Building the pseudo-header
directly stays loud.

The IP layer is parsed and built on its own here, as no next-layer fallback of an
enclosing layer quiets the refusal then.

"""
from __future__ import annotations

import ipaddress
import sys
import threading
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): exercises threading, locking or warning and exception hooks, which
#: differ by interpreter.
__tier__ = 'ALL'

V4_SRC, V4_DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('192.0.2.2')
V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')
#: The last address of a Routing header, which the pseudo-header takes as the destination.
FINAL = ipaddress.ip_address('2001:db8::99')

#: The refusal of a Routing header whose type is not parsed (RFC 8200 section 8.1).
ROUTE_ERROR = 'IP_Pseudo: final destination of Routing type 200 not parsed; give dst'


class VerifyUpperTestCase(unittest.TestCase):
    """Imports, exception-hook sentinels and helpers the tests share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # NOTE: Imported before the sentinels go in, since importing pcapkit
        # outside development mode installs tbtrim's hook itself.
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities import config
        from pcapkit.utilities.logging import logger

        self.Routing, self.Status, self.IPv4, self.IPv6 = Routing, ChecksumStatus, IPv4, IPv6
        self.IPv6_Frag, self.IPv6_Route, self.TCP = IPv6_Frag, IPv6_Route, TCP
        self.config, self.logger = config, logger

        saved = sys.excepthook, threading.excepthook

        def restore() -> None:
            sys.excepthook, threading.excepthook = saved

        self.addCleanup(restore)

        def sentinel(*args: 'object') -> None:
            sys.__excepthook__(*args)  # type: ignore[arg-type]

        def thread_sentinel(args: 'object') -> None:
            pass

        self.sentinels = sentinel, thread_sentinel
        sys.excepthook, threading.excepthook = self.sentinels

    def segment(self) -> object:
        """A TCP segment carrying a few octets."""
        return self.TCP(srcport=40000, dstport=80, payload=b'pending')

    def route(self, kind: int, **kwargs: object) -> object:
        """A Routing header of ``kind`` with a segment left, carrying a TCP segment."""
        return self.IPv6_Route(next=6, type=kind, seg_left=1, payload=self.segment(), **kwargs)

    def cases(self) -> 'dict[str, tuple[type, dict[str, object]]]':
        """Each IP layer as ``(class, make() arguments)``, by the refusal it meets."""
        return {
            # Type 200 is not parsed, so its final destination is unknown.
            'routing type 200': (self.IPv6, {'src': V6_SRC, 'dst': V6_DST, 'next': 43,
                                             'payload': self.route(200)}),
            'IPv6 first fragment': (self.IPv6, {'src': V6_SRC, 'dst': V6_DST, 'next': 44, 'payload':
                                                self.IPv6_Frag(next=6, mf=True, payload=self.segment())}),
            'IPv4 first fragment': (self.IPv4, {'src': V4_SRC, 'dst': V4_DST, 'protocol': 6, 'mf': True,
                                                'payload': self.segment()}),
        }

    def verified(self, klass: type, *args: object, **kwargs: object) -> 'tuple[object, list[tuple[str, str]]]':
        """``klass`` parsed or built under ``CHECKSUM_VERIFY``, and what it logged."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), capture(self.logger) as recorder, \
                warnings.catch_warnings():
            warnings.simplefilter('ignore')
            layer = klass(*args, **kwargs)
        return layer, recorder.messages

    def assertQuiet(self, layer: object, messages: 'list[tuple[str, str]]', status: object) -> None:
        """``layer``'s TCP segment is ``status``, and nothing was logged or hooked."""
        self.assertEqual((layer['TCP'].info.checksum_status, messages), (status, []))  # type: ignore[index]
        self.assertIs(sys.excepthook, self.sentinels[0])
        self.assertIs(threading.excepthook, self.sentinels[1])


class RefusedTests(VerifyUpperTestCase):
    """A pseudo-header the layer does not give is ``NO_PSEUDO_HEADER``, quietly."""

    def test_parsed(self) -> None:
        for name, (klass, kwargs) in self.cases().items():
            with self.subTest(name):
                octets = klass(**kwargs).data
                self.assertQuiet(*self.verified(klass, octets), self.Status.NO_PSEUDO_HEADER)

    def test_built(self) -> None:
        for name, (klass, kwargs) in self.cases().items():
            with self.subTest(name):
                self.assertQuiet(*self.verified(klass, **kwargs), self.Status.NO_PSEUDO_HEADER)

    def test_the_block_ends_with_the_verify(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo
        from pcapkit.utilities import exceptions
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import DEVMODE

        klass, kwargs = self.cases()['routing type 200']
        layer, _ = self.verified(klass, **kwargs)
        self.assertEqual(exceptions._caught_here.get(), ())  # pylint: disable=protected-access
        # Building the pseudo-header directly, with nothing to catch it, stays loud.
        with capture(self.logger) as recorder, self.assertRaises(ProtocolError) as context:
            IP_Pseudo(ip=layer)
        self.assertEqual(str(context.exception), ROUTE_ERROR)
        self.assertEqual(recorder.messages, [('CRITICAL', f'ProtocolError: {ROUTE_ERROR}')])
        if not DEVMODE:
            self.assertIsNot(sys.excepthook, self.sentinels[0])
            self.assertIsNot(threading.excepthook, self.sentinels[1])


class DerivedTests(VerifyUpperTestCase):
    """A pseudo-header the layer gives is verified as before, quietly."""

    def test_verified(self) -> None:
        cases = {
            # A Routing type parsed gives the final destination.
            'source route': (self.IPv6, {'src': V6_SRC, 'dst': V6_DST, 'next': 43,
                                         'payload': self.route(self.Routing.Source_Route,
                                                               data={'ip': [FINAL]})}),
            'atomic fragment': (self.IPv6, {'src': V6_SRC, 'dst': V6_DST, 'next': 44,
                                            'payload': self.IPv6_Frag(next=6, payload=self.segment())}),
            'IPv4': (self.IPv4, {'src': V4_SRC, 'dst': V4_DST, 'protocol': 6, 'payload': self.segment()}),
        }
        for name, (klass, kwargs) in cases.items():
            with self.subTest(name):
                layer, messages = self.verified(klass, **kwargs)
                self.assertQuiet(layer, messages, self.Status.VALID)
                self.assertQuiet(*self.verified(klass, layer.data), self.Status.VALID)  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
