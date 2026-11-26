# -*- coding: utf-8 -*-
"""The PCAP-NG engine hands its blocks no snaplen, and they parse the same (GitHub issue #2840).

A parse takes no ``__packet__`` since ``__init__`` closed its keywords, so the default
engine stopped handing each block interface 0's snaplen as ``__packet__['snaplen']``.
:meth:`PCAPNG.unpack <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.unpack>` reads the
same snaplen off the section context the engine hands it as ``ctx``. This guard
extracts every sample PCAP-NG capture twice, once with the engine's old call restored
through ``_from_parent``, and requires every block's info to be the same.

"""
from __future__ import annotations

import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SnaplenFromContextTests(unittest.TestCase):
    """Each sample PCAP-NG capture parses the same with and without the engine's snaplen."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def blocks(self, path: str, *, handed: bool) -> 'list[Any]':
        """Every block ``extract`` records of ``path``, as dicts, the snaplen ``handed`` in or not."""
        from pcapkit import extract
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        def with_snaplen(file: 'Any', length: 'Any' = None, /, *, num: int, sct: int, ctx: 'Any',
                         **stops: 'Any') -> 'Any':
            # NOTE: What the engine's ``_get_snaplen`` handed in before #2840.
            interfaces = getattr(ctx, 'interfaces', None)
            snaplen = interfaces[0].snaplen if interfaces and interfaces[0].snaplen else 0xFFFF_FFFF_FFFF_FFFF
            return PCAPNG._from_parent(file, length, {'num': num, 'sct': sct, 'ctx': ctx},  # pylint: disable=protected-access
                                       **stops, __packet__={'snaplen': snaplen})

        patch = mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', with_snaplen) if handed else mock.MagicMock()
        with patch, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=path, engine='default', store=True)
        self.addCleanup(close_extractor, extractor)
        return [frame.info.to_dict() for frame in extractor.frame]

    def test_every_block_parses_the_same(self) -> None:
        paths = (sample_path('dhcp.pcapng'), sample_path('dhcp_big_endian.pcapng'),
                 sample_path('dhcp_little_endian.pcapng'), sample_path('many_interfaces.pcapng'),
                 sample_path('test.pcapng'), sample_path('profile.pcapng'))
        for path in paths:
            with self.subTest(path=path):
                blocks = self.blocks(path, handed=False)
                self.assertTrue(blocks)
                self.assertEqual(blocks, self.blocks(path, handed=True))


if __name__ == '__main__':
    unittest.main()
