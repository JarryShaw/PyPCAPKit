# -*- coding: utf-8 -*-
"""A FRAD header rebuilds as captured and quietly at every cut, or is refused.

GitHub issue #2710: a :class:`~pcapkit.protocols.link.frad.protocol.FRAD` header the data ends
before its NLPID reads that octet as the ``0x00`` pad, so its data model holds an NLPID
of zero. :meth:`FRAD.make <pcapkit.protocols.link.frad.protocol.FRAD.make>` then left out the
``ext_nlpid`` the schema reads after the pad, and the rebuild logged ``NoDefaultValue``
at ``CRITICAL``. It writes the pad and an NLPID of zero instead, which the schema's own
short read cuts back.

The data model keeps no EA bits of the Q.922 address, so a header whose EA bits are not
the 2-octet form, ``0`` then ``1``, rebuilt other octets, cut or whole.
:meth:`FRAD.read <pcapkit.protocols.link.frad.protocol.FRAD.read>` refuses it, which a
:class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL` frame keeps as
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, quietly. An EA bit the data never held is not
checked.

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

#: Each frame cut at every octet: the RFC 2427 address of DLCI 50, UI control, then a
#: direct NLPID, a SNAP header, or the pad and an NLPID of zero.
FRAMES = {
    'direct': bytes.fromhex('0c21' '03' 'cc') + IPV4,
    'SNAP': bytes.fromhex('0c21' '03' '00' '80' '000000' '0806') + ARP,
    'pad, zero NLPID': bytes.fromhex('0c21' '03' '00' '00') + b'\xaa\xbb',
}

#: Addresses of DLCI 50 whose EA bits are not ``0`` then ``1``.
OTHER_FORMS = {
    'EA 1 then 1': bytes.fromhex('0d21'),
    'EA 0 then 0': bytes.fromhex('0c20'),
    'EA 1 then 0': bytes.fromhex('0d20'),
}

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


class FRADCutRebuildTests(unittest.TestCase):
    """A FRAD header rebuilds as captured, or the address form is refused."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.frad.protocol import FRAD
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2
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

    def test_every_cut_rebuilds_as_captured(self) -> None:
        for label, frame in FRAMES.items():
            for count in range(1, len(frame) + 1):
                with self.subTest(frame=label, captured=count):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        layer = self.FRAD(frame[:count], count)
                    self.assertEqual(layer.data, frame[:count])
                    self.assertRebuildsQuietly(layer)

    def test_a_cut_before_the_nlpid_reads_the_pad(self) -> None:
        for count in (1, 2, 3):
            with self.subTest(captured=count):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    layer = self.FRAD(FRAMES['direct'][:count], count)
                self.assertIsNotNone(layer.info.get('__short_read__'))
                self.assertEqual((layer.info.nlpid, layer.info.len), (0, 5))

    def test_make_writes_the_pad_and_a_zero_nlpid(self) -> None:
        made, messages = self.parse(lambda: self.FRAD(dlci=50, nlpid=0))
        self.assertEqual((made.data.hex(), messages), ('0c21030000', []))

    def test_another_address_form_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import CaughtByCaller

        for label, addr in OTHER_FORMS.items():
            frame = addr + FRAMES['direct'][2:]
            for count in range(2, len(frame) + 1):
                with self.subTest(address=label, captured=count), CaughtByCaller(self.ProtocolError), \
                        self.assertRaisesRegex(self.ProtocolError, r'^FRAD: not a 2-octet Q\.922 address: EA bits'):
                    self.FRAD(frame[:count], count)

    def test_an_ea_bit_cut_off_is_not_checked(self) -> None:
        # One octet holds the first EA bit alone: 0 reads, 1 is refused.
        from pcapkit.utilities.exceptions import CaughtByCaller

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            layer = self.FRAD(b'\x0c', 1)
        self.assertEqual(layer.info.get('__short_read__'), ('addr', 1))
        self.assertRebuildsQuietly(layer)
        with CaughtByCaller(self.ProtocolError), self.assertRaises(self.ProtocolError):
            self.FRAD(b'\x0d', 1)

    def test_linux_sll_keeps_another_address_form_raw(self) -> None:
        for name, (cls, head) in self.cooked.items():
            for label, addr in OTHER_FORMS.items():
                raw = head + addr + FRAMES['direct'][2:]
                with self.subTest(cooked=name, address=label):
                    frame, messages = self.parse(lambda: cls(raw, len(raw)))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(messages, [])
                    self.assertEqual(type(frame.payload).__name__, 'Raw')
                    self.assertRegex(frame.payload.info.error, r'^FRAD: not a 2-octet Q\.922 address: ')
                    self.assertEqual(frame.data, raw)
                    self.assertRebuildsQuietly(frame)

    def test_linux_sll_dispatches_the_2_octet_form(self) -> None:
        # The control: the RFC 2427 address is still FRAD behind LinuxSLL.
        for name, (cls, head) in self.cooked.items():
            raw = head + FRAMES['direct']
            with self.subTest(cooked=name):
                frame, messages = self.parse(lambda: cls(raw, len(raw)))  # pylint: disable=cell-var-from-loop
                self.assertEqual(messages, [])
                self.assertIsInstance(frame.payload, self.FRAD)
                self.assertRebuildsQuietly(frame)


if __name__ == '__main__':
    unittest.main()
