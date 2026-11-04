# -*- coding: utf-8 -*-
"""GitHub issue #2776: a PCAP-NG block rebuilt from its ``info`` reads what its parse read.

Octets after ``opt_endofopt`` rebuilt byte for byte (#1437), but ``make`` wrote
them as an item of the options, and the block rebuilt from its ``info`` read the
options as an area kept as captured: no options, and no ``padding_opts``. They
are written into the block's padding field after the options instead, where the
parse reads them from.

Every case builds its own octets in memory and reads no capture.

"""

import warnings
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_padding_kept_1437_unit import BLOCKS
from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: The cases that hold octets after ``opt_endofopt``, one per block type with an option area.
TRAILED = {name: octets for name, octets in BLOCKS.items() if name.endswith('octets after opt_endofopt')}


class TestPCAPNGTrailerInfo(PCAPNGTestCase):
    """Pin ``from_data(info).info == info`` for every padding case of #1437."""

    def _args(self, octets: 'bytes') -> 'dict[str, Any]':
        """The construction arguments ``_parse`` uses for ``octets``."""
        if octets[:4] == b'\x0a\x0d\x0d\x0a':
            return {'num': 0, 'sct': 1, 'ctx': None}
        return {'num': 2, 'sct': 1, 'ctx': self._context()}

    def test_every_block_type_with_an_option_area_has_a_case(self) -> None:
        self.assertEqual(sorted(name.split()[0] for name in TRAILED),
                         ['DSB', 'EPB', 'IDB', 'ISB', 'NRB', 'PB', 'SHB'])

    def test_the_parse_reads_the_trailer_as_padding(self) -> None:
        """Against the octets: the four before the trailing length, after an ``opt_endofopt``."""
        from pcapkit.const.pcapng.option_type import OptionType

        for name, octets in TRAILED.items():
            with self.subTest(name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                info = self._parse(octets).info
                self.assertEqual(info.padding_opts, octets[-8:-4])
                self.assertEqual(list(info.options)[-1], OptionType.opt_endofopt)

    def test_info_rebuilds_as_parsed(self) -> None:
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for name, octets in BLOCKS.items():
            for form in ('info', 'to_dict'):
                with self.subTest(name, form=form), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    args = self._args(octets)
                    info = PCAPNG(octets, len(octets), **args).info
                    rebuilt = PCAPNG.from_data(info if form == 'info' else info.to_dict(), **args)
                    self.assertEqual(rebuilt.data.hex(), octets.hex())
                    self.assertEqual(rebuilt.info.get('padding_opts'), info.get('padding_opts'))
                    if 'options' in info:
                        self.assertEqual(list(rebuilt.info.options.items(multi=True)),
                                         list(info.options.items(multi=True)))
                    self.assertEqual(rebuilt.info, info)


if __name__ == '__main__':
    import unittest
    unittest.main()
