# -*- coding: utf-8 -*-
"""A FRAD pad octet is kept, and never invented, through a rebuild.

GitHub issue #2716: :rfc:`2427#section-3` allows a single ``0x00`` pad octet ahead of
any NLPID, and :class:`~pcapkit.protocols.link.frad.FRAD` reads one ahead of every
NLPID, but its data model did not record whether one was there. So
:meth:`FRAD.make <pcapkit.protocols.link.frad.FRAD.make>` wrote the pad ahead of a
SNAP header alone: a pad before a direct NLPID was lost on a rebuild, and one was
invented ahead of a SNAP header captured without it. The data model's ``pad``
records it, and ``make()`` takes it, writing the pad ahead of a SNAP header alone
when it is not given.

The frames are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import contextlib
import logging
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: An IPv4 header (protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))
#: A minimal ARP request (RFC 826), 28 octets.
ARP = bytes.fromhex('00010800060400010011223344550a0000010000000000000a000002')

#: Each frame: the RFC 2427 address of DLCI 50 and UI control, then the NLPID with
#: or without the pad; its ``pad``, ``nlpid`` and header length; and its protocol chain.
FRAMES = {
    'pad, IPv4': (bytes.fromhex('0c21' '03' '00' 'cc') + IPV4, (True, 0xCC, 5), 'FRAD:IPv4:UDP'),
    'SNAP without the pad': (bytes.fromhex('0c21' '03' '80' '000000' '0806') + ARP, (False, 0x80, 9),
                             'FRAD:ARP'),
    # the forms the maker writes when ``pad`` is not given, as controls
    'IPv4': (bytes.fromhex('0c21' '03' 'cc') + IPV4, (False, 0xCC, 4), 'FRAD:IPv4:UDP'),
    'pad, SNAP': (bytes.fromhex('0c21' '03' '00' '80' '000000' '0806') + ARP, (True, 0x80, 10), 'FRAD:ARP'),
}  # type: dict[str, tuple[bytes, tuple[bool, int, int], str]]

#: A Linux cooked-capture source address, padded to its 8 octets.
LINK_ADDR = bytes.fromhex('001122334455') + bytes(2)


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.messages.append(f'logged: {record.getMessage()}')


@contextlib.contextmanager
def _reported() -> 'Iterator[list[str]]':
    """Collect what the block reports, on the :mod:`warnings` channel and the logger."""
    handler = _Logged()
    logger = logging.getLogger('pcapkit')
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            yield handler.messages
    finally:
        logger.removeHandler(handler)
    handler.messages.extend(f'warned: {item.message}' for item in caught)


class FRADPadRebuildTests(unittest.TestCase):
    """A FRAD frame rebuilds with the pad octet it was captured with, and no other."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.utilities.exceptions import ProtocolError

        self.FRAD = FRAD
        self.ProtocolError = ProtocolError
        self.cooked = {
            'LinuxSLL1': (LinuxSLL1, struct.pack('>HHH', 0, ARPHRD.FRAD, 6) + LINK_ADDR
                          + struct.pack('>H', 0)),
            'LinuxSLL2': (LinuxSLL2, struct.pack('>HHIHBB', 0, 0, 1, ARPHRD.FRAD, 0, 6) + LINK_ADDR),
        }  # type: dict[str, tuple[Any, bytes]]

    def parse(self, build: 'Callable[[], Any]') -> 'tuple[Any, list[str]]':
        """What ``build`` returns, and what it reported."""
        with _reported() as messages:
            layer = build()
        return layer, messages

    def assertRebuildsQuietly(self, layer: 'Any') -> 'None':  # pylint: disable=invalid-name
        """``layer`` rebuilt from its data model and its dict: its octets, and nothing reported."""
        for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
            with self.subTest(path=path):
                rebuilt, messages = self.parse(lambda: type(layer).from_data(data))  # pylint: disable=cell-var-from-loop
                self.assertEqual((rebuilt.data.hex(), messages), (layer.data.hex(), []))

    def test_a_whole_frame_reads_its_pad(self) -> None:
        for label, (frame, (pad, nlpid, length), chain) in FRAMES.items():
            with self.subTest(frame=label):
                layer, messages = self.parse(lambda: self.FRAD(frame, len(frame)))  # pylint: disable=cell-var-from-loop
                self.assertEqual(messages, [])
                self.assertEqual((layer.info.pad, layer.info.nlpid, layer.info.len), (pad, nlpid, length))
                self.assertEqual(str(layer.protochain), chain)

    def test_a_whole_frame_rebuilds_as_captured(self) -> None:
        for label, (frame, _, _) in FRAMES.items():
            with self.subTest(frame=label):
                layer = self.FRAD(frame, len(frame))
                self.assertRebuildsQuietly(layer)

    def test_every_cut_rebuilds_as_captured(self) -> None:
        for label, (frame, _, _) in FRAMES.items():
            for count in range(1, len(frame)):
                with self.subTest(frame=label, captured=count):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        layer = self.FRAD(frame[:count], count)
                    self.assertEqual(layer.data, frame[:count])
                    self.assertRebuildsQuietly(layer)

    def test_linux_sll_rebuilds_the_pad_as_captured(self) -> None:
        for name, (cls, head) in self.cooked.items():
            for label, (frame, (pad, _, _), chain) in FRAMES.items():
                raw = head + frame
                with self.subTest(cooked=name, frame=label):
                    sll, messages = self.parse(lambda: cls(raw, len(raw)))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(messages, [])
                    self.assertEqual(str(sll.protochain).split(':', 1)[1], chain)
                    self.assertIs(sll.payload.info.pad, pad)
                    self.assertRebuildsQuietly(sll)

    def test_make_writes_the_pad_ahead_of_snap_alone_by_default(self) -> None:
        # A direct build is as it was: the pad ahead of a SNAP header, and an
        # NLPID of 0 written as the pad it reads as.
        cases = {
            'IPv4': ({'nlpid': 0xCC}, '0c2103cc'),
            'SNAP': ({'nlpid': 0x80, 'snap_oui': bytes(3), 'snap_pid': 0x0806}, '0c2103008000000008' '06'),
            'zero NLPID': ({'nlpid': 0}, '0c21030000'),
        }
        for label, (kwargs, octets) in cases.items():
            with self.subTest(case=label):
                made, messages = self.parse(lambda: self.FRAD(dlci=50, **kwargs))  # pylint: disable=cell-var-from-loop
                self.assertEqual((made.data.hex(), messages), (octets, []))

    def test_make_takes_the_pad(self) -> None:
        cases = {
            'pad, IPv4': ({'nlpid': 0xCC, 'pad': True}, '0c2103' '00cc'),
            'IPv4 without the pad': ({'nlpid': 0xCC, 'pad': False}, '0c2103' 'cc'),
            'SNAP without the pad': ({'nlpid': 0x80, 'pad': False, 'snap_oui': bytes(3), 'snap_pid': 0x0806},
                                     '0c2103' '80' '000000' '0806'),
            'pad, zero NLPID': ({'nlpid': 0, 'pad': True}, '0c2103' '0000'),
        }
        for label, (kwargs, octets) in cases.items():
            with self.subTest(case=label):
                made, messages = self.parse(lambda: self.FRAD(dlci=50, **kwargs))  # pylint: disable=cell-var-from-loop
                self.assertEqual((made.data.hex(), messages), (octets, []))
                self.assertIs(self.FRAD(made.data, len(made.data)).info.pad, kwargs['pad'])

    def test_make_refuses_a_zero_nlpid_without_the_pad(self) -> None:
        from pcapkit.utilities.exceptions import CaughtByCaller

        with CaughtByCaller(self.ProtocolError), self.assertRaisesRegex(
                self.ProtocolError, r'^FRAD: an nlpid of 0 reads as the pad, so pad cannot be False$'):
            self.FRAD(nlpid=0, pad=False)


if __name__ == '__main__':
    unittest.main()
