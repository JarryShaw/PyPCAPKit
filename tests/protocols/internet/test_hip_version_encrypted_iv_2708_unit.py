# -*- coding: utf-8 -*-
"""HIP builds version 2 by default, and ``ENCRYPTED`` carries an IV with an AES cipher alone.

GitHub issue #2708, three defects of :class:`~pcapkit.protocols.internet.hip.protocol.HIP`:

* **Version.** :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`'s
  ``__post_init__`` defaults ``version`` to 6, the IP version, and hands it on
  to :meth:`HIP.make <pcapkit.protocols.internet.hip.protocol.HIP.make>`, which writes it
  as the HIP version. HIP's own ``__post_init__`` takes ``version`` with
  ``make``'s default, so ``HIP(next=59, parameters=[])`` writes version 2, as
  ``make`` called directly does. Version 6 is no HIP version:
  :rfc:`7401#section-5.1` gives 2, and :rfc:`5201` 1. While parsing, the keyword
  is the enclosing IP layer's version and the octets decide.
* **IV.** ``ENCRYPTED`` writes an IV for ``AES-128-CBC`` and ``AES-256-CBC``
  alone (:rfc:`7401#section-5.2.18`). An IV given with any other cipher would
  count in Length while the schema drops it, and the packet would not parse
  back, so the maker refuses it, from a data model as from keywords.
* **Cipher on parse.** ``ENCRYPTED``'s schema takes its cipher from the
  ``HIP_CIPHER`` parameters before it in the area, the Nth ``ENCRYPTED`` the
  Nth cipher ID. Each parameter of the area is unpacked with one shared
  context, and ``HIP_CIPHER`` records its cipher IDs there. The parsed
  parameters themselves never reach that context, so a lookup through them
  would find none, warn of a missing ``HIP_CIPHER`` and read an AES IV as
  encrypted data. A parameter with no ``HIP_CIPHER`` before it still warns.

The ciphers are read off :class:`~pcapkit.const.hip.cipher.Cipher`, with one
code it does not assign.

Every case builds its own octets in memory and reads no capture. :class:`HIP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import inspect
import unittest
import warnings

from tests._support import reimport_once_per_class

#: A cipher code :class:`~pcapkit.const.hip.cipher.Cipher` assigns no member.
UNASSIGNED_CIPHER = 0x1234


class TestHIPDefaultVersion(unittest.TestCase):
    """A HIP header constructed without ``version`` is the one ``make`` writes."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_constructor_writes_make_default(self) -> None:
        from pcapkit.protocols.internet.hip.protocol import HIP

        default = inspect.signature(HIP.make).parameters['version'].default
        self.assertEqual(default, 2)

        for kwargs in ({'next': 59}, {'next': 59, 'parameters': []}):
            with self.subTest(**kwargs):
                proto = HIP(**kwargs)
                self.assertEqual(proto.info.version, default)
                # Version 2, three reserved zero bits, then the fixed bit 1.
                self.assertEqual(proto.data[3], 0x21)
                self.assertEqual(proto.data, HIP(version=default, **kwargs).data)
                self.assertEqual(proto.data, proto.make(**kwargs).pack())

    def test_explicit_version_is_written(self) -> None:
        from pcapkit.protocols.internet.hip.protocol import HIP

        for version in (1, 2):
            with self.subTest(version=version):
                proto = HIP(next=59, version=version)
                self.assertEqual(proto.info.version, version)
                self.assertEqual(proto.data[3], version << 4 | 0x01)

    def test_parse_reads_version_from_octets(self) -> None:
        from pcapkit.protocols.internet.hip.protocol import HIP

        for version in (1, 2):
            data = HIP(next=59, version=version).data
            for ip_version in (4, 6):
                with self.subTest(version=version, ip_version=ip_version):
                    parsed = HIP(data, version=ip_version)
                    self.assertEqual(parsed.info.version, version)
                    self.assertEqual(HIP.from_data(parsed.info).data, data)


class TestHIPEncryptedIV(unittest.TestCase):
    """``ENCRYPTED`` takes an IV with the AES ciphers and with no other."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _build(cipher: 'object', iv: 'bytes | None') -> 'bytes':
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP

        return HIP(next=59, parameters=[
            (Parameter.HIP_CIPHER, {'ciphers': [cipher]}),
            (Parameter.ENCRYPTED, {'cipher': cipher, 'iv': iv, 'data': b'abcd'}),
        ]).data

    @staticmethod
    def _ciphers() -> 'tuple[list[object], list[object]]':
        from pcapkit.const.hip.cipher import Cipher

        aes = [Cipher.AES_128_CBC, Cipher.AES_256_CBC]
        others = [member for member in Cipher if member not in aes]  # type: list[object]
        others.append(UNASSIGNED_CIPHER)
        return list(aes), others

    def test_other_cipher_refuses_an_iv(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        _, others = self._ciphers()
        self.assertTrue(others)
        for cipher in others:
            for iv in (b'', bytes(16)):
                with self.subTest(cipher=cipher, iv=iv):
                    with self.assertRaisesRegex(ProtocolError, 'IV is not used by cipher'):
                        self._build(cipher, iv)

    def test_data_model_with_other_cipher_refuses_an_iv(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.data import EncryptedParameter
        from pcapkit.protocols.internet.hip.protocol import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        _, others = self._ciphers()
        for cipher in others:
            for iv in (None, bytes(16)):
                with self.subTest(cipher=cipher, iv=iv):
                    param = EncryptedParameter(type=Parameter.ENCRYPTED, critical=True, length=8,
                                               reserved=bytes(4), cipher=cipher, iv=iv, data=b'abcd')
                    if iv is None:
                        schema = HIP()._make_param_encrypted(Parameter.ENCRYPTED, param, version=2)
                        self.assertEqual(bytes(schema), b'\x02\x81\x00\x08' + bytes(4) + b'abcd' + bytes(4))
                    else:
                        with self.assertRaisesRegex(ProtocolError, 'IV is not used by cipher'):
                            HIP()._make_param_encrypted(Parameter.ENCRYPTED, param, version=2)

    def test_other_cipher_without_iv_round_trips(self) -> None:
        from pcapkit.protocols.internet.hip.protocol import HIP

        _, others = self._ciphers()
        for cipher in others:
            with self.subTest(cipher=cipher):
                data = self._build(cipher, None)
                # ENCRYPTED, after the HIP_CIPHER parameter: Length 8 is the
                # four reserved octets and the data, with no IV.
                self.assertEqual(data[48:52], b'\x02\x81\x00\x08')
                self.assertEqual(data[56:60], b'abcd')
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = HIP(data)
                    self.assertEqual(HIP.from_data(parsed.info).data, data)

    def test_aes_cipher_writes_its_iv(self) -> None:
        aes, _ = self._ciphers()
        for cipher in aes:
            with self.subTest(cipher=cipher):
                data = self._build(cipher, bytes(range(16)))
                # Length 24: the reserved octets, the 16-octet IV and the data.
                self.assertEqual(data[48:52], b'\x02\x81\x00\x18')
                self.assertEqual(data[56:72], bytes(range(16)))
                self.assertEqual(data[72:76], b'abcd')


class TestHIPEncryptedCipherOnParse(unittest.TestCase):
    """A parsed ``ENCRYPTED`` takes its cipher from the ``HIP_CIPHER`` before it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, data: 'bytes') -> 'tuple[object, list[str]]':
        """Parse ``data`` as HIP, returning the layer and the warnings it drew."""
        from pcapkit.protocols.internet.hip.protocol import HIP

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = HIP(data)
        return parsed, [str(warning.message) for warning in caught]

    def test_each_cipher_reads_its_own_layout(self) -> None:
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP

        aes, others = TestHIPEncryptedIV._ciphers()  # pylint: disable=protected-access
        for cipher in [*aes, *others]:
            iv = bytes(range(16)) if cipher in aes else None
            with self.subTest(cipher=cipher):
                data = TestHIPEncryptedIV._build(cipher, iv)  # pylint: disable=protected-access
                parsed, caught = self._parse(data)
                self.assertEqual(caught, [])
                (encrypted,) = parsed.info.parameters.getlist(Parameter.ENCRYPTED)
                self.assertEqual(int(encrypted.cipher), int(cipher))
                self.assertIsInstance(encrypted.cipher, Cipher)
                self.assertEqual(encrypted.iv, iv)
                self.assertEqual(encrypted.data, b'abcd')
                self.assertEqual(HIP.from_data(parsed.info).data, data)

    def test_each_encrypted_takes_the_next_cipher(self) -> None:
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP

        ciphers = [Cipher.AES_256_CBC, Cipher.NULL_ENCRYPT, Cipher.AES_128_CBC]
        ivs = [bytes(16), None, bytes(range(16))]
        data = HIP(next=59, parameters=[
            (Parameter.HIP_CIPHER, {'ciphers': ciphers[:1]}),
            (Parameter.HIP_CIPHER, {'ciphers': ciphers[1:]}),
            *[(Parameter.ENCRYPTED, {'cipher': cipher, 'iv': iv, 'data': b'abcd'})
              for cipher, iv in zip(ciphers, ivs)],
        ]).data
        parsed, caught = self._parse(data)
        self.assertEqual(caught, [])
        encrypted = parsed.info.parameters.getlist(Parameter.ENCRYPTED)
        self.assertEqual([param.cipher for param in encrypted], ciphers)
        self.assertEqual([param.iv for param in encrypted], ivs)
        self.assertEqual(HIP.from_data(parsed.info).data, data)

    def test_without_a_cipher_for_it_still_warns(self) -> None:
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP

        lone = HIP(next=59, parameters=[
            (Parameter.ENCRYPTED, {'cipher': Cipher.NULL_ENCRYPT, 'data': b'abcd'}),
        ]).data
        extra = HIP(next=59, parameters=[
            (Parameter.HIP_CIPHER, {'ciphers': [Cipher.NULL_ENCRYPT]}),
            (Parameter.ENCRYPTED, {'cipher': Cipher.NULL_ENCRYPT, 'data': b'abcd'}),
            (Parameter.ENCRYPTED, {'cipher': Cipher.NULL_ENCRYPT, 'data': b'efgh'}),
        ]).data
        for data, message in ((lone, 'missing HIP_CIPHER parameter'),
                              (extra, 'too many ENCRYPTED parameters')):
            with self.subTest(message=message):
                parsed, caught = self._parse(data)
                self.assertEqual(len(caught), 1)
                self.assertIn(message, caught[0])
                self.assertEqual(HIP.from_data(parsed.info).data, data)


if __name__ == '__main__':
    unittest.main()
