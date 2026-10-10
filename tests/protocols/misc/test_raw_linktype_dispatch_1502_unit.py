# -*- coding: utf-8 -*-
"""GitHub issue #1502: ``LINKTYPE_RAW`` (101) is dissected as IPv4 or IPv6.

Neither :attr:`Frame.__proto__ <pcapkit.protocols.misc.pcap.frame.Frame.__proto__>`
nor :attr:`PCAPNG.__proto__ <pcapkit.protocols.misc.pcapng.PCAPNG.__proto__>`
had an entry for ``LinkType.RAW``, so a raw-IP frame was kept as
:class:`~pcapkit.protocols.misc.raw.Raw` and never reached reassembly. It
carries a bare IPv4 or IPv6 datagram that only the version nibble tells apart,
so both now dispatch it as ``IPV4`` or ``IPV6`` by that nibble, unless ``RAW``
itself is registered.

Every layer is rebuilt byte-exactly, from ``info`` and from ``info.to_dict()``.
Each capture is built here and written to a temporary directory. Everything from
:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.protocols.link.test_loopback_unit import IPV4, IPV6, _pcap, _pcapng

#: Records of a raw-IP capture, and the protocol chain each one reads as.
RECORDS = ((IPV4, 'IPv4:UDP'), (IPV6, 'IPv6:UDP'), (b'\x50' + IPV4[1:], 'RAW'))
FORMATS = ((_pcap, '.pcap'), (_pcapng, '.pcapng'))


class TestRawLinktypeDispatch(unittest.TestCase):
    """Pin how both capture formats dispatch a raw-IP frame."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, octets: bytes, suffix: str):  # type: ignore[no-untyped-def]
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f'raw{suffix}')
            with open(path, 'wb') as file:
                file.write(octets)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                return pcapkit.extract(fin=path, nofile=True, store=True, reassembly=True, ip=True)

    @staticmethod
    def _keywords(frame):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.misc.pcap.frame import Frame

        if isinstance(frame, Frame):
            return {'num': frame._fnum, 'header': frame._ghdr}
        return {'num': frame._fnum, 'sct': frame._sect, 'ctx': frame._ctx}

    def test_version_nibble_selects_the_layer(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload

        for build, suffix in FORMATS:
            with self.subTest(format=suffix):
                extractor = self._extract(build(101, [record for record, _ in RECORDS]), suffix)
                self.assertEqual([frame.protochain.chain for frame in extractor.frame],
                                 [chain for _, chain in RECORDS])
                self.assertEqual(len(extractor.reassembly.ipv4), 1)
                for frame in extractor.frame:
                    layer, keywords = frame, self._keywords(frame)
                    while not isinstance(layer, NoPayload):
                        for data in (layer.info, layer.info.to_dict()):
                            with self.subTest(frame=frame.info.number, layer=type(layer).__name__,
                                              data=type(data).__name__):
                                self.assertEqual(type(layer).from_data(data, **keywords).data.hex(),
                                                 layer.data.hex())
                        layer, keywords = layer.payload, {}

    def test_dispatch_reaches_what_ipv4_is_registered_against(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.misc.raw import Raw

        marker = type('W1502Marker', (Raw,), {'__module__': __name__})
        for (build, suffix), cls in zip(FORMATS, (Frame, PCAPNG)):
            with self.subTest(format=suffix), mock.patch.dict(cls.__proto__, {LinkType.IPV4: marker}):
                extractor = self._extract(build(101, [IPV4]), suffix)
                self.assertIsInstance(extractor.frame[0].payload, marker)

    def test_an_entry_registered_under_raw_is_used_as_it_stands(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.misc.raw import Raw

        marker = type('W1502RawMarker', (Raw,), {'__module__': __name__})
        for (build, suffix), cls in zip(FORMATS, (Frame, PCAPNG)):
            with self.subTest(format=suffix), mock.patch.dict(cls.__proto__, {LinkType.RAW: marker}):
                extractor = self._extract(build(101, [IPV4, IPV6]), suffix)
                self.assertEqual([type(frame.payload) for frame in extractor.frame], [marker, marker])

    def test_raw_is_not_registered(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertNotIn(LinkType.RAW, cls.__proto__)


if __name__ == '__main__':
    unittest.main()
