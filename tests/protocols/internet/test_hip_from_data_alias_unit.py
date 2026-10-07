# -*- coding: utf-8 -*-
"""HIP's ``alias`` is readable while the header is still being decoded.

GitHub issue #1184: :attr:`HIP.alias <pcapkit.protocols.internet.hip.HIP.alias>`
read ``self._info.version``. Outside an IPv6 extension chain,
:meth:`HIP.read <pcapkit.protocols.internet.hip.HIP.read>` ends in
``_decode_next_layer``, which reads ``alias`` for the protocol chain, but
``_info`` is assigned only once ``read`` has returned. So parsing or
constructing a standalone HIP header, and
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` over a parsed one,
raised ``AttributeError: 'HIP' object has no attribute '_info'``.

Every case builds its own octets in memory and reads no capture. :class:`HIP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here, as in
#: :data:`examples.generators.options.HIP_BASE`.
HIP_BASE = {
    'next': 59, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestHIPFromDataAlias(unittest.TestCase):
    """Pin ``alias`` on the paths that decode a next layer."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _parameters() -> 'list':
        from pcapkit.const.hip.parameter import Parameter

        return [(Parameter.R1_COUNTER, {'counter': 0x0123456789abcdef})]

    def _octets(self, version: 'int') -> 'bytes':
        from pcapkit.protocols.internet.hip import HIP

        return HIP(parameters=self._parameters(), extension=True,
                   version=version, **HIP_BASE).data

    def test_construct_standalone_header(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for version in (1, 2):
            with self.subTest(version=version):
                proto = HIP(parameters=self._parameters(), version=version, **HIP_BASE)
                self.assertEqual(proto.alias, f'HIPv{version}')
                self.assertEqual(proto.data, self._octets(version))

    def test_parse_standalone_header(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for version in (1, 2):
            with self.subTest(version=version):
                octets = self._octets(version)
                proto = HIP(octets, len(octets))
                self.assertEqual(proto.alias, f'HIPv{version}')
                self.assertEqual(str(proto.protochain).split(':')[0], f'HIPv{version}')

    def test_from_data_rebuilds_extension_header_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for version in (1, 2):
            with self.subTest(version=version):
                octets = self._octets(version)
                parsed = HIP(octets, len(octets), extension=True)
                rebuilt = HIP.from_data(parsed.info)
                self.assertEqual(rebuilt.data, octets)
                self.assertEqual(rebuilt.alias, f'HIPv{version}')
                self.assertEqual(rebuilt.info.version, version)


if __name__ == '__main__':
    unittest.main()
