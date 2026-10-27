# -*- coding: utf-8 -*-
"""HIP parameters carry the units, widths and registries their RFCs define.

Seven defects in :mod:`pcapkit.protocols.internet.hip`, each a field read or
written against the wrong definition:

* #2271 -- ``TRANSACTION_ID`` (:rfc:`6078#section-4.4`) and ``OVERLAY_ID``
  (:rfc:`6079#section-6.1`) size their rebuilt ``Length`` from
  :meth:`int.bit_length`, which cannot see a leading zero octet, so an
  identifier read with ``Length = 4`` was written back as ``Length = 1``.
* #2275 -- ``HIP_TRANSFORM`` is :rfc:`5201` only and its reader says so, but
  its maker had no version gate and built octets that reader rejects.
* #2276 -- a ``LOCATOR_SET`` locator built with ``spi=`` left ``type`` at ``0``
  while setting ``Locator Length`` to ``5``, a pair
  :func:`~pcapkit.protocols.schema.internet.hip.locator_value_selector`
  refuses; :rfc:`8046#section-4.2` makes the SPI form Type 1.
* #2281 -- ``REG_INFO``, ``REG_REQUEST`` and ``REG_RESPONSE`` read their
  lifetime octets as counts of seconds, where :rfc:`8003#section-4.1` makes a
  non-zero octet an exponent standing for ``2^((lifetime - 64)/8)`` seconds.
* #2282 -- ``OVERLAY_TTL``'s ``ttl`` parsed as a :class:`~datetime.timedelta`,
  but :rfc:`6079#section-6.2` gives it as "the number of overlay hops this
  packet has left".
* #2283 -- ``CERT``'s group decoded through the Diffie-Hellman group registry,
  so a group of ``7`` read back as the curve ``NIST_P_256``;
  :rfc:`8002#section-2` leaves that namespace to each sending host.
* #2299 -- ``HOST_ID``'s maker prefixed its errors ``[HIPv2]`` rather than the
  ``HIPv{version}: [ParamNo {code}]`` every other HIP message uses.

Every case builds its own octets in memory and reads no capture. :class:`HIP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""

import datetime
import importlib.util
import io
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: Offset of the first parameter: the 8-octet fixed header plus the two HITs.
PARAM_OFFSET = 40


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPWireSemanticsTests(unittest.TestCase):
    """One test per defect, each pinning the RFC's own reading of the field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    # -- helpers ----------------------------------------------------------

    def _packet(self, code: 'object', value: 'object', version: 'int' = 2) -> 'bytes':
        """Build a whole HIP packet carrying the one parameter ``code``."""
        from pcapkit.protocols.internet.hip import HIP

        return HIP(parameters=[(code, value)], extension=True,
                   version=version, **HIP_BASE).data  # type: ignore[arg-type]

    def _params(self, code: 'object', value: 'object', version: 'int' = 2) -> 'bytes':
        """Just the parameter octets of such a packet."""
        return self._packet(code, value, version)[PARAM_OFFSET:]

    def _wrap(self, raw: 'bytes', version: 'int' = 2) -> 'bytes':
        """Build a whole HIP packet whose parameter octets are ``raw``."""
        from pcapkit.protocols.internet.hip import HIP

        return HIP(parameters=[raw], extension=True,
                   version=version, **HIP_BASE).data

    def _parse(self, code: 'object', raw: 'bytes', version: 'int' = 2) -> 'object':
        """Parse the parameter octets ``raw`` and return the parsed data."""
        from pcapkit.protocols.internet.hip import HIP

        wire = self._wrap(raw, version)
        return HIP(io.BytesIO(wire), len(wire), extension=True).info.parameters[code]  # type: ignore[index]

    # -- #2271 ------------------------------------------------------------

    def test_an_identifier_rebuilds_at_the_width_it_was_read_with(self) -> None:
        """#2271: leading zero octets survive a parse-rebuild round trip."""
        from pcapkit.const.hip.parameter import Parameter

        # ``len=4, id=1`` -- three leading zero octets, which ``bit_length``
        # cannot see and the padded ``length`` cannot recover.
        for code, raw_hex in ((Parameter.TRANSACTION_ID, '11e4000400000001'),
                              (Parameter.OVERLAY_ID, '11f0000400000001')):
            with self.subTest(code=code):
                raw = bytes.fromhex(raw_hex)
                parsed = self._parse(code, raw)

                self.assertEqual(parsed.id, 1)  # type: ignore[attr-defined]
                self.assertEqual(parsed.id_len, 4)  # type: ignore[attr-defined]
                # The whole point: byte-exact, where it used to come back as
                # ``...000101000000``.
                self.assertEqual(self._params(code, parsed).hex(), raw_hex)

    def test_an_identifier_width_may_be_declared_or_inferred(self) -> None:
        """#2271: ``id_len`` overrides, and ``bit_length`` is the fallback."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.utilities.exceptions import ProtocolError

        for code in (Parameter.TRANSACTION_ID, Parameter.OVERLAY_ID):
            with self.subTest(code=code):
                # Declared width wins, so a from-scratch build can ask for the
                # padded form.
                self.assertEqual(
                    self._params(code, {'id': 1, 'id_len': 4})[2:4].hex(), '0004')
                # With nothing declaring it, the value's own width is all there
                # is -- the documented fallback, not a regression.
                self.assertEqual(
                    self._params(code, {'id': 1})[2:4].hex(), '0001')
                # A width too narrow for the value is refused rather than
                # silently truncating the identifier.
                with self.assertRaisesRegex(ProtocolError, 'invalid identifier width'):
                    self._params(code, {'id': 0x1234, 'id_len': 1})

    # -- #2275 ------------------------------------------------------------

    def test_hip_transform_is_refused_outside_version_1(self) -> None:
        """#2275: the *maker* gates on version, as its own reader does.

        The maker is called directly rather than through
        :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>`, because a
        whole-packet build raised this same message from
        ``_read_param_hip_transform`` all along -- the packet is parsed back on
        the way out. Going through the public path therefore cannot tell a
        gated maker from an ungated one, which is the distinction the issue is
        about: the maker used to return ``0241000200010000`` for HIPv2, octets
        its own reader rejects.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.hip.suite import Suite
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = HIP.__new__(HIP)
        suites = [Suite.AES_CBC_with_HMAC_SHA1]

        with self.assertRaisesRegex(
                ProtocolError, rf'HIPv2: \[ParamNo {Parameter.HIP_TRANSFORM}\] invalid parameter'):
            proto._make_param_hip_transform(Parameter.HIP_TRANSFORM, version=2, suites=suites)

        # HIPv1, where :rfc:`5201#section-5.2.7` does define it, still builds --
        # both through the maker and all the way through a packet.
        self.assertEqual(
            proto._make_param_hip_transform(
                Parameter.HIP_TRANSFORM, version=1, suites=suites).pack().hex(),
            '0241000200010000')
        self.assertEqual(
            self._params(Parameter.HIP_TRANSFORM, {'suites': suites}, version=1).hex(),
            '0241000200010000')

    # -- #2276 ------------------------------------------------------------

    def test_a_locator_with_an_spi_needs_no_explicit_type(self) -> None:
        """#2276: ``spi=`` alone builds an :rfc:`8046` Locator Type 1."""
        from pcapkit.const.hip.parameter import Parameter

        derived = self._params(Parameter.LOCATOR_SET,
                               {'locator_set': [{'ip': '2001:db8::1', 'spi': 7}]})
        restated = self._params(Parameter.LOCATOR_SET,
                                {'locator_set': [{'ip': '2001:db8::1',
                                                  'type': 1, 'spi': 7}]})

        # ``spi=`` alone used to raise ``FieldValueError: invalid locator type
        # or length``; it now agrees with the form that restates the type.
        self.assertEqual(derived.hex(), restated.hex())
        # Locator Type 1, Locator Length 5 -- the SPI plus a 128-bit address.
        self.assertEqual(derived[4:7].hex(), '000105')

    def test_a_locator_without_an_spi_is_type_0(self) -> None:
        """#2276: the plain-address form is unchanged."""
        from pcapkit.const.hip.parameter import Parameter

        octets = self._params(Parameter.LOCATOR_SET,
                              {'locator_set': [{'ip': '2001:db8::1'}]})
        self.assertEqual(octets[4:7].hex(), '000004')

    def test_a_locator_type_contradicting_its_spi_is_refused(self) -> None:
        """#2276: a stated ``type`` that disagrees with ``spi`` raises."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.utilities.exceptions import ProtocolError

        # Type 1 promises an SPI that is not there.
        with self.assertRaisesRegex(ProtocolError, 'invalid locator type: 1 does not match spi None'):
            self._params(Parameter.LOCATOR_SET,
                         {'locator_set': [{'ip': '2001:db8::1', 'type': 1}]})
        # Type 0 has no room for the SPI that was given.
        with self.assertRaisesRegex(ProtocolError, 'invalid locator type: 0 does not match spi 7'):
            self._params(Parameter.LOCATOR_SET,
                         {'locator_set': [{'ip': '2001:db8::1', 'type': 0, 'spi': 7}]})

    # -- #2281 ------------------------------------------------------------

    def test_registration_lifetime_octets_decode_per_rfc_8003(self) -> None:
        """#2281: a non-zero octet is an exponent, and ``0`` means zero."""
        from pcapkit.const.hip.parameter import Parameter

        # ``(code, octet, expected)``. The two endpoints are the ones
        # :rfc:`8003#section-4.1` names: ``2^(-63/8)`` is "~4 ms" and
        # ``2^(191/8)`` is "~178 days".
        cases = (
            (0, datetime.timedelta(0)),
            (1, datetime.timedelta(seconds=2 ** (-63 / 8))),
            (64, datetime.timedelta(seconds=1)),
            (72, datetime.timedelta(seconds=2)),
            (255, datetime.timedelta(seconds=2 ** (191 / 8))),
        )

        for octet, expected in cases:
            with self.subTest(octet=octet):
                for code, key in ((Parameter.REG_REQUEST, 'reg_request'),
                                  (Parameter.REG_RESPONSE, 'reg_response')):
                    raw = self._params(code, {'lifetime_exponent': octet, key: [1]})
                    parsed = self._parse(code, raw)

                    # The octet read as a count of seconds was the bug: 64 was
                    # reported as 64 seconds rather than as one second.
                    self.assertEqual(parsed.lifetime, expected)  # type: ignore[attr-defined]
                    self.assertEqual(parsed.lifetime_exponent, octet)  # type: ignore[attr-defined]

        # ``REG_INFO`` carries two of them.
        raw = self._params(Parameter.REG_INFO,
                           {'min_lifetime_exponent': 0,
                            'max_lifetime_exponent': 255, 'reg_info': [1]})
        lifetime = self._parse(Parameter.REG_INFO, raw).lifetime  # type: ignore[attr-defined]
        self.assertEqual(lifetime.min, datetime.timedelta(0))
        self.assertEqual(lifetime.max, datetime.timedelta(seconds=2 ** (191 / 8)))
        self.assertEqual((lifetime.min_exponent, lifetime.max_exponent), (0, 255))
        # ~178 days, as the RFC's own prose says.
        self.assertEqual(lifetime.max.days, 178)

    def test_a_registration_lifetime_duration_encodes_to_its_octet(self) -> None:
        """#2281: the makers take a duration and encode it per the RFC."""
        from pcapkit.const.hip.parameter import Parameter

        # One second is octet 64, not octet 1; the old maker wrote 1.
        self.assertEqual(
            self._params(Parameter.REG_REQUEST,
                         {'lifetime': datetime.timedelta(seconds=1),
                          'reg_request': [1]})[4], 64)
        self.assertEqual(
            self._params(Parameter.REG_REQUEST, {'lifetime': 2, 'reg_request': [1]})[4], 72)
        # Zero is the RFC's reserved cancellation value rather than an error.
        self.assertEqual(
            self._params(Parameter.REG_REQUEST, {'lifetime': 0, 'reg_request': [1]})[4], 0)
        # REG_INFO's pair, both as durations.
        octets = self._params(Parameter.REG_INFO,
                              {'min_lifetime': 1, 'max_lifetime': 2, 'reg_info': [1]})
        self.assertEqual((octets[4], octets[5]), (64, 72))

    def test_every_registration_lifetime_octet_round_trips(self) -> None:
        """#2281: the raw octet is the rebuild source, so all 256 survive.

        Decoding to a :class:`~datetime.timedelta` and encoding back from it
        cannot do this -- most of the 256 octets have no exact duration, which
        is why the octet is kept beside it, as ``PUZZLE``'s is (#1323).

        """
        from pcapkit.const.hip.parameter import Parameter

        for code, key in ((Parameter.REG_REQUEST, 'reg_request'),
                          (Parameter.REG_RESPONSE, 'reg_response')):
            for octet in range(256):
                with self.subTest(code=code, octet=octet):
                    raw = self._params(code, {'lifetime_exponent': octet, key: [1]})
                    self.assertEqual(raw[4], octet)
                    parsed = self._parse(code, raw)
                    self.assertEqual(self._params(code, parsed).hex(), raw.hex())

    def test_an_out_of_range_registration_lifetime_is_refused(self) -> None:
        """#2281: neither a negative duration nor a wide octet is written."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'invalid lifetime'):
            self._params(Parameter.REG_REQUEST,
                         {'lifetime': datetime.timedelta(seconds=-1), 'reg_request': [1]})
        # ``UInt8Field`` wraps rather than raising, so 300 would otherwise be
        # written as some other valid-looking duration.
        with self.assertRaisesRegex(ProtocolError, 'invalid lifetime'):
            self._params(Parameter.REG_REQUEST,
                         {'lifetime_exponent': 300, 'reg_request': [1]})
        # Past ``2^(191/8)`` seconds the octet no longer fits.
        with self.assertRaisesRegex(ProtocolError, 'invalid lifetime'):
            self._params(Parameter.REG_REQUEST,
                         {'lifetime': datetime.timedelta(days=365 * 10), 'reg_request': [1]})

    # -- #2282 ------------------------------------------------------------

    def test_overlay_ttl_is_a_hop_count(self) -> None:
        """#2282: ``ttl`` is an :obj:`int`, not a duration."""
        from pcapkit.const.hip.parameter import Parameter

        raw = self._params(Parameter.OVERLAY_TTL, {'ttl': 5})
        self.assertEqual(raw.hex(), 'fa0b000400050000')

        parsed = self._parse(Parameter.OVERLAY_TTL, raw)
        # It used to come back as ``timedelta(seconds=5)``.
        self.assertEqual(parsed.ttl, 5)  # type: ignore[attr-defined]
        self.assertIsInstance(parsed.ttl, int)  # type: ignore[attr-defined]
        self.assertNotIsInstance(parsed.ttl, datetime.timedelta)  # type: ignore[attr-defined]
        self.assertEqual(self._params(Parameter.OVERLAY_TTL, parsed).hex(), raw.hex())

    # -- #2283 ------------------------------------------------------------

    def test_cert_group_is_a_plain_octet(self) -> None:
        """#2283: no registry stands behind ``CERT group``."""
        from pcapkit.const.hip.parameter import Parameter

        raw = self._params(Parameter.CERT,
                           {'cert_group': 7, 'cert_count': 1,
                            'cert_id': 1, 'cert': b'x'})
        parsed = self._parse(Parameter.CERT, raw)

        # ``7`` used to decode as ``<Group.NIST_P_256: 7>``, a Diffie-Hellman
        # curve name on a field :rfc:`8002#section-2` leaves to the sender.
        self.assertEqual(parsed.cert_group, 7)  # type: ignore[attr-defined]
        self.assertIs(type(parsed.cert_group), int)  # type: ignore[attr-defined]
        self.assertEqual(self._params(Parameter.CERT, parsed).hex(), raw.hex())

    def test_cert_group_defaults_to_zero(self) -> None:
        """#2283: the default is neutral, not a curve name."""
        from pcapkit.const.hip.parameter import Parameter

        self.assertEqual(self._params(Parameter.CERT, {'cert': b'x'})[4], 0)

    def test_cert_group_takes_no_enum_lookup_arguments(self) -> None:
        """#2283: the namespace arguments existed only for the wrong registry."""
        import inspect

        from pcapkit.protocols.internet.hip import HIP

        keywords = inspect.signature(HIP._make_param_cert).parameters
        for dropped in ('cert_group_default', 'cert_group_namespace',
                        'cert_group_reversed'):
            self.assertNotIn(dropped, keywords)
        # ``cert_type`` keeps its own, since :rfc:`8002` really does register it.
        self.assertIn('cert_type_namespace', keywords)

    # -- #2299 ------------------------------------------------------------

    def test_host_id_errors_use_the_house_prefix(self) -> None:
        """#2299: ``HIPv2: [ParamNo 705] ...``, not ``[HIPv2] ...``."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.data.internet.hip import HostIdentity
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = HIP.__new__(HIP)
        expected = rf"^HIPv2: \[ParamNo {Parameter.HOST_ID}\] invalid curve: 'bogus'$"

        # The ``hi_curve`` branch.
        with self.assertRaisesRegex(ProtocolError, expected):
            proto._make_param_host_id(Parameter.HOST_ID, hi_curve='bogus',  # type: ignore[arg-type]
                                      hi_pub_key=b'', version=2)
        # The branch for a ``HostIdentity`` passed as ``hi``.
        with self.assertRaisesRegex(ProtocolError, expected):
            proto._make_param_host_id(Parameter.HOST_ID,
                                      hi=HostIdentity(curve='bogus', pubkey=b''),  # type: ignore[arg-type]
                                      version=2)


if __name__ == '__main__':
    unittest.main()
