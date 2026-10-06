# -*- coding: utf-8 -*-
"""``_make_data`` returns the keywords ``make()`` takes.

GitHub issue #1097: :meth:`Frame._make_data
<pcapkit.protocols.misc.pcap.frame.Frame._make_data>` returned ``ts_src`` where
:meth:`Frame.make <pcapkit.protocols.misc.pcap.frame.Frame.make>` takes
``ts_sec``, and :meth:`L2TPv2._make_data
<pcapkit.protocols.link.l2tpv2.L2TPv2._make_data>` returned ``prio`` where
:meth:`L2TPv2.make <pcapkit.protocols.link.l2tpv2.L2TPv2.make>` takes
``priority``. :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`
discards such a key with an
:class:`~pcapkit.utilities.warnings.UnknownFieldWarning`, so the field was lost
on a round-trip. Each case here rebuilds a packet with ``from_data`` and checks
both that the field survives and that nothing was discarded.

Every case builds its own packet in memory, so this belongs to the unit tier.

"""
from __future__ import annotations

import importlib.util
import io
import unittest
import warnings

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class MakeDataKeysTests(unittest.TestCase):
    """A ``from_data`` round-trip keeps every field ``_make_data`` returns."""

    def assertNoUnknownField(self, caught: 'list[warnings.WarningMessage]') -> None:
        from pcapkit.utilities.warnings import UnknownFieldWarning

        discarded = [str(item.message) for item in caught
                     if isinstance(item.message, UnknownFieldWarning)]
        self.assertEqual(discarded, [])

    def test_l2tpv2_priority_survives_from_data(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        octets = bytes(L2TPv2(version=2, priority=True, tunnel_id=1, session_id=2))
        parsed = L2TPv2(io.BytesIO(octets), len(octets))
        self.assertTrue(parsed.info.flags.prio)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = L2TPv2.from_data(parsed.info)

        self.assertNoUnknownField(caught)
        self.assertTrue(rebuilt.info.flags.prio)
        self.assertEqual(bytes(rebuilt), octets)

    def test_frame_ts_sec_survives_from_data(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header(network=1)
        frame = Frame(num=1, header=header.info, ts_sec=1234, ts_usec=5,
                      packet=b'\x00' * 14)

        # NOTE: The frame index and the global header are not part of the
        # frame's data, so they are passed to :meth:`from_data` alongside it.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = Frame.from_data(frame.info, num=1, header=header.info)

        self.assertNoUnknownField(caught)
        self.assertEqual(rebuilt.info.frame_info.ts_sec, 1234)
        self.assertEqual(rebuilt.info.frame_info.ts_usec, 5)
        self.assertEqual(rebuilt.info.frame_info.incl_len, 14)
        self.assertEqual(rebuilt.info.frame_info.orig_len, 14)


if __name__ == '__main__':
    unittest.main()
