# -*- coding: utf-8 -*-
"""A refusal ``analyze`` absorbs is quiet, and its ``Raw`` names the code (#2862).

``Protocol.analyze`` and ``Transport.analyze`` keep a payload that fails to parse as
``Raw``. As the per-frame fallback does (#2588, #2308), each entry point -- the two
methods, ``ip_datagram`` for IPv4 and IPv6, ``tcp_datagram``, and the ``Deferred``
packet IP and TCP reassembly store -- logs nothing, lets no warning of the failed
parse escape, leaves both exception hooks alone, and keeps the ``error`` and the
``protocol`` the per-frame ``Raw`` keeps for the same octets. An error other than a
refusal is logged at WARNING, as ``beholder`` logs it. A parse that is kept still
reports its warnings, its own after those of the layers it carries.

Every packet is built in memory; no sample capture is read.

"""

from __future__ import annotations

import collections
import ipaddress
import struct
import sys
import threading
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import install_hook_sentinels, reimport_once_per_class
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): exercises the warning and exception hooks, which differ by interpreter.
__tier__ = 'ALL'

V4_SRC, V4_DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2')
V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')

#: A TCP segment whose Data Offset is 0, which TCP refuses.
SEGMENT = bytes(range(30))
#: An HTTP request, which TLS on port 443 refuses while warning ``packet length < 0``.
REQUEST = b'GET / HTTP/1.1\r\nHost: example\r\n\r\n'
#: The ports ``REQUEST`` is carried between; only 443 is registered.
SPORT, DPORT = 1234, 443


def _ipv4(payload: bytes) -> bytes:
    """An IPv4 header, DF set, carrying ``payload`` as TCP."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, 6, 0,
                       V4_SRC.packed, V4_DST.packed) + payload


def _ipv6(payload: bytes) -> bytes:
    """An IPv6 header carrying ``payload`` as TCP."""
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), 6, 64,
                       V6_SRC.packed, V6_DST.packed) + payload


def _tcp(payload: bytes) -> bytes:
    """A TCP header from :data:`SPORT` to :data:`DPORT` carrying ``payload``."""
    return struct.pack('!HHIIBBHHH', SPORT, DPORT, 1, 1, 5 << 4, 0x18, 0xFFFF, 0, 0) + payload


def _frame(klass: 'Any', data: bytes) -> 'Any':
    """The payload layer of ``klass`` parsed from ``data``, whatever it warns."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return klass(data).payload


def _ports() -> 'tuple[Any, Any]':
    """:data:`SPORT` and :data:`DPORT` as TCP application types."""
    from pcapkit.const.reg.apptype import TCP as AppType_TCP

    return AppType_TCP.get(SPORT), AppType_TCP.get(DPORT)


class FromParent:
    """A stand-in next layer, which the library builds through ``_from_parent`` (#2840)."""

    @classmethod
    def _from_parent(cls, file: 'Any', length: int, extra: 'Any' = None, /, **kwargs: 'Any') -> 'Any':
        return cls(file, length, **(extra or {}), **kwargs)  # type: ignore[call-arg]


def _layer(refuse: bool) -> type:
    """A stand-in next layer that warns, then refuses its octets if ``refuse``."""
    from pcapkit.utilities.exceptions import ProtocolError
    from pcapkit.utilities.warnings import ProtocolWarning, warn

    class Layer(FromParent):
        def __init__(self, file: 'Any', length: int, **kwargs: 'Any') -> None:
            warn('stand-in warning', ProtocolWarning)
            if refuse:
                raise ProtocolError('stand-in refusal')
            self.data = file.read(length)

    return Layer


def _carrier() -> type:
    """A stand-in next layer that warns before and after an inner layer it parses, which warns."""
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.utilities.warnings import ProtocolWarning, warn

    class Inner(FromParent):
        def __init__(self, file: 'Any', length: int, **kwargs: 'Any') -> None:
            warn('inner', ProtocolWarning)

    class Carrier(FromParent):
        def __init__(self, file: 'Any', length: int, **kwargs: 'Any') -> None:
            warn('outer-1', ProtocolWarning)
            self.data = file.read(length)
            self.inner = ProtocolBase._parse_next_layer(Inner, self.data, len(self.data))
            warn('outer-2', ProtocolWarning)

    return Carrier


def _broken() -> type:
    """A stand-in next layer that fails with an error other than a refusal."""

    class Broken(FromParent):
        def __init__(self, file: 'Any', length: int, **kwargs: 'Any') -> None:
            raise ValueError('stand-in bug')

    return Broken


class AnalyzeRefusalQuietTests(unittest.TestCase):
    """Every entry point to the fallback is quiet, and names the code it was dispatched on."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # NOTE: Imported before the sentinels go in, since importing pcapkit
        # outside development mode installs tbtrim's hook itself.
        import pcapkit  # pylint: disable=import-outside-toplevel,unused-import
        self.sentinels = install_hook_sentinels(self)

    def run_quietly(self, func: 'Callable[..., Any]', *args: 'Any') -> 'Any':
        """``func(*args)``, asserting it logs nothing, warns nothing and hooks nothing."""
        from pcapkit.utilities.logging import logger

        with capture(logger) as recorder, warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            result = func(*args)
        self.assertEqual(recorder.messages, [])
        self.assertEqual([str(warning.message) for warning in caught], [])
        self.assertIs(sys.excepthook, self.sentinels[0])
        self.assertIs(threading.excepthook, self.sentinels[1])
        return result

    def assertFallback(self, result: 'Any', payload: bytes, frame: 'Any') -> None:
        """``result`` keeps ``payload`` with the ``error`` and ``protocol`` of ``frame``."""
        from pcapkit.protocols.misc.raw.protocol import Raw

        self.assertIs(type(frame), Raw)
        self.assertIsNotNone(frame.info.protocol)

        self.assertIs(type(result), Raw)
        self.assertEqual(bytes(result), payload)
        self.assertEqual(result.info.error, frame.info.error)
        self.assertEqual(result.info.protocol, frame.info.protocol)
        self.assertIs(type(result.info.protocol), type(frame.info.protocol))
        self.assertEqual(str(result.protochain), str(frame.protochain))

    def _ip_frames(self) -> 'Any':
        """Each IP protocol, with the ``Raw`` its per-frame parse keeps of :data:`SEGMENT`."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for protocol, build in ((IPv4, _ipv4), (IPv6, _ipv6)):
            yield protocol, _frame(protocol, build(SEGMENT))

    def test_protocol_analyze(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        for protocol, frame in self._ip_frames():
            with self.subTest(protocol=protocol.__name__):
                result = self.run_quietly(protocol.analyze, TransType.TCP, SEGMENT)
                self.assertFallback(result, SEGMENT, frame)
                self.assertIs(result.info.protocol, TransType.TCP)

    def test_transport_analyze(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = _frame(TCP, _tcp(REQUEST))
        result = self.run_quietly(TCP.analyze, _ports(), REQUEST)
        self.assertFallback(result, REQUEST, frame)
        self.assertEqual(result.info.protocol, DPORT)

    def test_ip_datagram(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.ip.data import Datagram, DatagramID
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for protocol, frame in self._ip_frames():
            with self.subTest(protocol=protocol.__name__):
                src, dst = (V6_SRC, V6_DST) if protocol is IPv6 else (V4_SRC, V4_DST)
                datagram = Datagram(completed=Completion.COMPLETE,
                                    id=DatagramID(src=src, dst=dst, id=1, proto=TransType.TCP),
                                    index=(1,), header=b'', payload=SEGMENT, packet=None, conflict=())
                self.assertFallback(self.run_quietly(ip_datagram, datagram), SEGMENT, frame)

    def test_tcp_datagram(self) -> None:
        from pcapkit.foundation.analysis import tcp_datagram
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.tcp.data import Datagram, DatagramID
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = _frame(TCP, _tcp(REQUEST))
        datagram = Datagram(completed=Completion.COMPLETE,
                            id=DatagramID(src=(V4_SRC, SPORT), dst=(V4_DST, DPORT), ack=1),
                            index=(1,), header=b'', payload=REQUEST, packet=None, conflict=())
        self.assertFallback(self.run_quietly(tcp_datagram, datagram), REQUEST, frame)

    def test_deferred_ip_packet(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data import Deferred
        from pcapkit.foundation.reassembly.ip.data import Packet
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4 as IPv4_Reassembly
        from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6 as IPv6_Reassembly
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        engines = {'IPv4': IPv4_Reassembly, 'IPv6': IPv6_Reassembly}
        for protocol, frame in self._ip_frames():
            with self.subTest(protocol=protocol.__name__):
                src, dst = (V6_SRC, V6_DST) if protocol is IPv6 else (V4_SRC, V4_DST)
                reassembly = engines[protocol.__name__]()
                for num, (fo, mf, part) in enumerate(((0, True, SEGMENT[:16]),
                                                      (16, False, SEGMENT[16:])), 1):
                    reassembly(Packet((src, dst, 1, TransType.TCP), num, fo, 20, mf,
                                      20 + len(part), b'', bytearray(part), float(num)))
                datagram, = reassembly.datagram
                self.assertIsInstance(datagram.__dict__[datagram.__map__.get('packet', 'packet')],
                                      Deferred)
                self.assertFallback(self.run_quietly(getattr, datagram, 'packet'), SEGMENT, frame)

    def test_deferred_tcp_packet(self) -> None:
        from functools import partial

        from pcapkit.foundation.analysis.tcp import _analyze_payload
        from pcapkit.foundation.reassembly.data import Deferred
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = _frame(TCP, _tcp(REQUEST))
        deferred = Deferred(partial(_analyze_payload, TCP), _ports(), REQUEST)
        self.assertFallback(self.run_quietly(deferred), REQUEST, frame)

    def _analyzers(self, layer: type) -> 'Any':
        """``Protocol.analyze`` and ``Transport.analyze`` of classes dispatching code 80 to ``layer``."""
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.transport import Transport

        class DummyInternet(Internet):
            __proto__ = collections.defaultdict(lambda: Raw, {80: layer})

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: Raw, {80: layer})

        yield 'Protocol.analyze', DummyInternet.analyze, 80
        yield 'Transport.analyze', DummyTransport.analyze, (80, 60000)

    def test_failed_parse_drops_its_warnings(self) -> None:
        """The stand-in's warning and refusal reach neither channel; ``error`` keeps the refusal."""
        for name, analyze, key in self._analyzers(_layer(refuse=True)):
            with self.subTest(analyze=name):
                result = self.run_quietly(analyze, key, b'payload')
                self.assertEqual(bytes(result), b'payload')
                self.assertEqual(result.info.error, 'stand-in refusal')
                self.assertEqual(result.info.protocol, 80)

    def test_kept_parse_reports_its_warnings_after_its_inner_layers(self) -> None:
        """A kept parse warns once per warning on each channel, its own after its inner layer's.

        The parse's own warnings are held until it is kept, as a frame's layer's are, while
        the inner layer reports its own as it ends; before #2862 they came in call order.
        """
        from pcapkit.utilities.logging import logger

        layer = _carrier()
        order = ['inner', 'outer-1', 'outer-2']
        for name, analyze, key in self._analyzers(layer):
            with self.subTest(analyze=name):
                with capture(logger) as recorder, warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    result = analyze(key, b'payload')
                self.assertIsInstance(result, layer)
                self.assertEqual(result.data, b'payload')
                self.assertEqual(recorder.messages, [('WARNING', message) for message in order])
                self.assertEqual([str(warning.message) for warning in caught], order)
                self.assertEqual({warning.filename for warning in caught}, {__file__})

    def test_other_error_is_logged_at_warning(self) -> None:
        """An error other than a refusal is logged once at WARNING, as ``beholder`` logs it."""
        from pcapkit.utilities.logging import logger

        for name, analyze, key in self._analyzers(_broken()):
            with self.subTest(analyze=name):
                with capture(logger) as recorder, warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    result = analyze(key, b'payload')
                self.assertEqual(recorder.messages, [('WARNING', 'stand-in bug')])
                self.assertEqual(recorder.records[0].name, 'pcapkit.protocols.protocol')
                self.assertEqual(caught, [])
                self.assertEqual(bytes(result), b'payload')
                self.assertEqual(result.info.error, 'stand-in bug')
                self.assertEqual(result.info.protocol, 80)


if __name__ == '__main__':
    unittest.main()
