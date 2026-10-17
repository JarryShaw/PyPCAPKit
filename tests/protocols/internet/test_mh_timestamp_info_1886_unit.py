# -*- coding: utf-8 -*-
"""``NTPTimestamp`` and ``PMIPv6Timestamp`` are ``Info`` data models (GitHub issue #1886).

Both were named tuples in :mod:`pcapkit.protocols.internet.mh`. They are now
:class:`~pcapkit.protocols.data.data.Data` models in
:mod:`pcapkit.protocols.data.internet.mh`, beside the options that hold them, so
:meth:`~pcapkit.corekit.infoclass.Info.from_dict` can resolve the annotations of
those options and rebuild them. These checks pin what that changes:

* each is an :class:`~pcapkit.corekit.infoclass.Info`, read by attribute and no
  longer a tuple;
* a Mobility Header carrying the option that holds it rebuilds byte for byte,
  from its info and from ``info.to_dict()``;
* the dumpers write it keyed by field;
* it survives :mod:`pickle`.

Every case builds its packet as octets in memory and reads no capture.

"""

import importlib.util
import json
import os
import pickle
import plistlib
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: NTP seconds and fraction of the Mobility Message Replay Protection option:
#: the UNIX epoch counted from 1900, plus a quarter of a second.
NTP = (0x83aa7e80, 0x40000000)
#: :rfc:`5213#section-8.8` seconds and fraction of the Timestamp option: a
#: 48-bit UNIX time, plus half a second in 1/65536ths.
PMIP = (1_700_000_000, 0x8000)

#: A Binding Refresh Request (type 0) with no next header, carrying the
#: Mobility Message Replay Protection option (type 10), the Timestamp option
#: (type 27) and a PadN that aligns it to 32 octets, i.e. ``Header Len`` 3.
MH_OCTETS = (bytes([59, 3, 0, 0]) + b'\x00\x00' + b'\x00\x00'
             + bytes([10, 8]) + struct.pack('!II', *NTP)
             + bytes([27, 8]) + PMIP[0].to_bytes(6, 'big') + PMIP[1].to_bytes(2, 'big')
             + bytes([1, 2, 0, 0]))

MAC = bytes.fromhex('0123456789ab' 'fedcba987654')
SRC6 = bytes.fromhex('20010db8' + '00' * 11 + '01')
DST6 = bytes.fromhex('20010db8' + '00' * 11 + '02')

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')


def capture() -> 'bytes':
    """A PCAP file of one Ethernet/IPv6 frame whose next header is :data:`MH_OCTETS`."""
    packet = (MAC + b'\x86\xdd'
              + struct.pack('!IHBB16s16s', 6 << 28, len(MH_OCTETS), 135, 64, SRC6, DST6)
              + MH_OCTETS)
    return GLOBAL + struct.pack('<IIII', 1, 2, len(packet), len(packet)) + packet


def find(node: 'object', key: 'str') -> 'list[object]':
    """Every value held under ``key`` by a mapping anywhere inside ``node``."""
    found = []  # type: list[object]
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                found.append(value)
            found.extend(find(value, key))
    elif isinstance(node, list):
        for value in node:
            found.extend(find(value, key))
    return found


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class MHTimestampInfoTests(unittest.TestCase):
    """Both timestamps are data models, as the other nested values of the MH models are."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def parse(self) -> 'tuple[object, object, object]':
        """The parsed header, and its replay protection and timestamp options."""
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        info = MH(MH_OCTETS, extension=True).info
        return (info, info.options[Option.MESG_ID_OPTION_TYPE],
                info.options[Option.Timestamp_Option])

    def test_both_are_info_data_models_read_by_attribute(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.protocols.data.data import Data
        from pcapkit.protocols.data.internet import mh as data
        from pcapkit.utilities.exceptions import UnsupportedCall

        _, mesg_id, timestamp = self.parse()
        for name, value, model, expected in (
            ('ntp_timestamp', mesg_id.ntp_timestamp, 'NTPTimestamp', NTP),
            ('pmip_timestamp', timestamp.pmip_timestamp, 'PMIPv6Timestamp', PMIP),
        ):
            with self.subTest(field=name):
                self.assertIsInstance(value, Info)
                self.assertIsInstance(value, Data)
                self.assertNotIsInstance(value, tuple)
                cls = getattr(data, model)
                self.assertIs(type(value), cls)
                self.assertEqual((value.seconds, value.fraction), expected)
                self.assertEqual(list(value), ['seconds', 'fraction'])

                # constructed positionally or by keyword alike, and immutable
                self.assertEqual(cls(*expected), value)
                self.assertEqual(cls(seconds=expected[0], fraction=expected[1]), value)
                with self.assertRaises(UnsupportedCall):
                    value.seconds = 0  # type: ignore[misc]

                # the option's annotation resolves at runtime, so the nested
                # model comes back as itself rather than as a plain mapping
                option = mesg_id if name == 'ntp_timestamp' else timestamp
                rebuilt = type(option).from_dict(option.to_dict())
                self.assertIs(type(rebuilt[name]), cls)
                self.assertEqual(rebuilt, option)

    def test_a_header_carrying_each_option_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        info, _, _ = self.parse()
        for label, source in (('info', info), ('info.to_dict()', info.to_dict())):
            with self.subTest(source=label):
                self.assertEqual(MH.from_data(source).data, MH_OCTETS)

    def test_the_dumpers_key_each_by_field(self) -> None:
        from pcapkit import extract

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'in.pcap')
            with open(src, 'wb') as file:
                file.write(capture())
            dumps = {}
            for fmt in ('json', 'plist'):
                extractor = extract(fin=src, fout=os.path.join(tmpdir, f'out-{fmt}'),
                                    format=fmt, store=False)
                with open(extractor.output, 'rb') as file:
                    dumps[fmt] = file.read()

        for fmt, tree in (('json', json.loads(dumps['json'])),
                          ('plist', plistlib.loads(dumps['plist']))):
            for key, (seconds, fraction) in (('ntp_timestamp', NTP), ('pmip_timestamp', PMIP)):
                with self.subTest(format=fmt, field=key):
                    self.assertEqual(find(tree, key), [{'seconds': seconds, 'fraction': fraction}])

    def test_pickling_round_trips(self) -> None:
        from pcapkit.corekit.infoclass import Info

        _, mesg_id, timestamp = self.parse()
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            for value in (mesg_id.ntp_timestamp, timestamp.pmip_timestamp, mesg_id, timestamp):
                with self.subTest(protocol=protocol, type=type(value).__name__):
                    restored = pickle.loads(pickle.dumps(value, protocol))
                    self.assertIsInstance(restored, Info)
                    self.assertIs(type(restored), type(value))
                    self.assertEqual(restored, value)
            for value, expected in ((mesg_id.ntp_timestamp, NTP), (timestamp.pmip_timestamp, PMIP)):
                restored = pickle.loads(pickle.dumps(value, protocol))
                self.assertEqual((restored.seconds, restored.fraction), expected)


if __name__ == '__main__':
    unittest.main()
