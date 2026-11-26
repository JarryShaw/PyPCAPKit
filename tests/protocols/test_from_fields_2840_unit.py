# -*- coding: utf-8 -*-
"""``Proto.from_fields(**fields)`` constructs a protocol (GitHub issue #2840).

The owner took the plan on #2840 that splits parsing from construction. This
module pins the construct side:

* :class:`FromFieldsTests` -- :meth:`~pcapkit.protocols.protocol.Protocol.from_fields`
  builds every edge round trip's case, as calling the class with its fields does
  (#3081), refuses a parse keyword, a stop,
  ``__context__`` and an undeclared ``packet`` with
  :exc:`~pcapkit.utilities.exceptions.UnexpectedKeyword`, which is a
  :exc:`TypeError` as well, takes ``context``, and hands a field named like a stop
  to ``make``;
* :class:`VersionedBaseTests` -- through a versioned family's base, ``version``
  picks the member, and a member refuses another's ``version``, through
  ``from_data`` too;
* :class:`FromDataTests` -- ``from_data`` takes ``data`` positionally and
  ``context`` by name, refuses ``__context__`` and the stops, warns on a key its
  ``_make_data`` gives, and the default ``_make_data`` leaves out an undeclared
  ``packet``;
* :class:`NoLegacyKeywordTests` -- the out-of-band keywords ``Proto(**fields)``
  took are gone, refused by the class call as by ``from_fields``.

This module is unit tier: it constructs its own octets and reads no capture.

"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import inspect
import io
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.protocols import _edge_roundtrip as edge

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises metaclass and signature machinery, which differs by
#: interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The HMAC-SHA-256-128 key of the Security Association the ESP cases build with,
#: whose ``ENCR_NULL`` cipher needs no :mod:`cryptography`.
ESP_KEY = bytes(range(32))

#: A TCP header spelled as :meth:`TCP.make <pcapkit.protocols.transport.tcp.protocol.TCP.make>`
#: declares it.
TCP_FIELDS = {'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'syn': True, 'window': 8192}

#: Modules whose ``MAKE_CASES`` are the ``make`` calls of the edge round trips.
EDGE_MODULES = (
    'tests.protocols.link.test_link_edge_roundtrip_unit',
    'tests.protocols.internet.test_internet_edge_roundtrip_unit',
    'tests.protocols.transport.test_transport_edge_roundtrip_unit',
    'tests.protocols.application.test_application_edge_roundtrip_unit',
)


def _make_cases() -> 'list[edge.MakeCase]':
    """Every ``MakeCase`` of :data:`EDGE_MODULES`."""
    import importlib  # pylint: disable=import-outside-toplevel

    cases = []  # type: list[edge.MakeCase]
    for name in EDGE_MODULES:
        cases.extend(importlib.import_module(name).MAKE_CASES)
    return cases


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FromFieldsTests(unittest.TestCase):
    """``from_fields`` builds from fields, and from fields alone."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_the_class_call_builds_as_from_fields_does(self) -> 'None':
        """Each edge ``MakeCase`` builds the same octets through either form (#3081)."""
        cases = _make_cases()
        self.assertTrue(cases)
        for case in cases:
            with self.subTest(case=case.label), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                cls = edge.resolve(case.cls)
                built = cls.from_fields(**case.kwargs)
                self.assertEqual(cls(built.data, len(built.data)).data, built.data)
                self.assertEqual(cls(**case.kwargs).data, built.data)

    def test_parse_keywords_stops_and_the_old_context_are_refused(self) -> 'None':
        """Each is refused by name, with the closest keyword it may have meant."""
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import UnexpectedKeyword

        suggested = {'seq': 'seq_no', '__context__': 'context', 'packet': '__packet__'}
        for key in ('bogus', 'seq', 'file', 'length', 'layer', '_layer', '_protocol',
                    '__context__', 'packet'):
            with self.subTest(key=key):
                with self.assertRaises(UnexpectedKeyword) as context:
                    TCP.from_fields(**TCP_FIELDS, **{key: None})
                message = str(context.exception)
                self.assertIn(f'TCP: unexpected keyword(s): {key!r}', message)
                if key in suggested:
                    self.assertIn(f'(did you mean {suggested[key]!r}?)', message)

    def test_the_refusal_is_a_type_error_and_an_unsupported_call(self) -> 'None':
        """``except TypeError`` catches it, as it catches Python's own refusal."""
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import UnexpectedKeyword, UnsupportedCall

        self.assertTrue(issubclass(UnexpectedKeyword, TypeError))
        self.assertTrue(issubclass(UnexpectedKeyword, UnsupportedCall))
        with self.assertRaises(TypeError):
            TCP.from_fields(seq=1)

    def test_the_signature_is_context_and_fields(self) -> 'None':
        """``from_fields(*, context=None, **fields)``, on the base every class inherits."""
        from pcapkit.protocols.protocol import ProtocolBase

        params = inspect.signature(ProtocolBase.from_fields).parameters
        self.assertEqual([(name, param.kind) for name, param in params.items()],
                         [('context', inspect.Parameter.KEYWORD_ONLY),
                          ('fields', inspect.Parameter.VAR_KEYWORD)])
        self.assertIsNone(params['context'].default)

    def test_a_field_named_as_a_stop_is_a_field(self) -> 'None':
        """IPv4's ``protocol`` field goes to ``make``, and no stop is set."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        ipv4 = IPv4.from_fields(protocol=TransType.TCP, src='192.0.2.1', dst='192.0.2.2')
        self.assertEqual(ipv4.info.protocol, TransType.TCP)
        self.assertIsNone(ipv4._exproto)  # pylint: disable=protected-access
        self.assertIsNone(ipv4._exlayer)  # pylint: disable=protected-access

    def test_the_context_is_adopted(self) -> 'None':
        """A registry given as ``context`` is the one the instance holds."""
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.transport.tcp.protocol import TCP

        registry = ContextRegistry()
        self.assertIs(TCP.from_fields(**TCP_FIELDS, context=registry)._exctx,  # pylint: disable=protected-access
                      registry)

    def test_esp_protects_with_the_context(self) -> 'None':
        """``ESP.from_fields(encrypt=True, context=...)`` uses that context's Security Association."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp.protocol import ESP, ESPContext, Integrity, SecurityAssociation
        from pcapkit.utilities.exceptions import ProtocolError

        sa = SecurityAssociation(spi=0x77, integrity=Integrity.HMAC_SHA2_256_128, integrity_key=ESP_KEY)
        registry = ContextRegistry.make(ESPContext(sa))
        built = ESP.from_fields(spi=0x77, seq=1, next=TransType.UDP, encrypt=True,
                                payload=b'plaintext', context=registry)
        wire = bytes(built)
        self.assertEqual(wire[-16:], hmac.new(ESP_KEY, wire[:-16], hashlib.sha256).digest()[:16])
        self.assertEqual(ESP(wire, len(wire), context=registry).info.plaintext, b'plaintext')

        with self.assertRaisesRegex(ProtocolError, 'no security association for SPI'):
            ESP.from_fields(spi=0x77, seq=1, next=TransType.UDP, encrypt=True, payload=b'plaintext')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class VersionedBaseTests(unittest.TestCase):
    """``version`` picks a versioned family's member, and is checked on a member."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_the_base_builds_the_member_version_names(self) -> 'None':
        """Each base gives its member, never an instance of itself."""
        from pcapkit.const.http.frame import Frame as Enum_Frame
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.application.httpv1.protocol import HTTPv1
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.igmpv2.protocol import IGMPv2
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        built = (
            (IP.from_fields(version=4, src='192.0.2.1', dst='192.0.2.2'), IPv4),
            (ICMP.from_fields(version=6), ICMPv6),
            (IGMP.from_fields(version=2, max_resp_time=100), IGMPv2),
            (L2TP.from_fields(version=2), L2TPv2),
            (LinuxSLL.from_fields(version=2), LinuxSLL2),
            (HTTP.from_fields(version=1, method='GET', uri='/'), HTTPv1),
            (HTTP.from_fields(version=2, type=Enum_Frame.SETTINGS), HTTPv2),
        )
        for proto, member in built:
            with self.subTest(member=member.__name__):
                self.assertIs(type(proto), member)

        # a member takes its own version, or none, and the version is no field of it
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

        for member, own, fields in ((IPv4, 4, {}), (ICMPv4, 4, {}), (IGMPv2, 2, {'max_resp_time': 100}),
                                    (LinuxSLL1, 1, {}), (L2TPv2, 2, {}), (HTTPv1, 1, {'method': 'GET', 'uri': '/'})):
            with self.subTest(own=member.__name__):
                self.assertEqual(member.from_fields(version=own, **fields).data, member.from_fields(**fields).data)
        self.assertEqual(IP.from_fields(version=4).data, IPv4.from_fields().data)

    def test_a_missing_or_foreign_version_is_refused(self) -> 'None':
        """No version through a base; another member's version on a member."""
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.application.httpv1.protocol import HTTPv1
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.igmpv2.protocol import IGMPv2
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
        from pcapkit.utilities.exceptions import ProtocolError

        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4

        refused = (
            (lambda: IP.from_fields(), 'IP: no version to build with'),
            (lambda: ICMP.from_fields(), 'ICMP: no version to build with'),
            (lambda: IGMP.from_fields(), 'IGMP: no version to build with'),
            (lambda: L2TP.from_fields(), 'L2TP: no version to build with'),
            (lambda: LinuxSLL.from_fields(), 'LinuxSLL: no version to build with'),
            (lambda: HTTP.from_fields(method='GET'), 'HTTP: no version to build with'),
            (lambda: IP.from_fields(version=5), 'IP: invalid version: 5'),
            (lambda: IPv4.from_fields(version=6), 'IPv4: version=6 names another member'),
            (lambda: ICMPv4.from_fields(version=6), 'ICMPv4: version=6 names another member'),
            (lambda: IGMPv2.from_fields(version=3), 'IGMPv2: version=3 names another member'),
            (lambda: LinuxSLL1.from_fields(version=2), 'LinuxSLL1: version=2 names another member'),
            (lambda: HTTPv1.from_fields(version=2), 'HTTPv1: version=2 names another member'),
            (lambda: HTTP.from_fields(version=1, preface=True, method='GET'),
             'HTTP/1: connection preface is HTTP/2 only'),
        )
        for build, message in refused:
            with self.subTest(message=message):
                with self.assertRaises(ProtocolError) as context:
                    build()
                self.assertIn(message, str(context.exception))

    def test_from_data_keeps_the_member_check(self) -> 'None':
        """``IPv4.from_data(data, version=6)`` is refused, as a construction is."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        info = IPv4.from_fields(src='192.0.2.1', dst='192.0.2.2').info
        self.assertEqual(IPv4.from_data(info, version=4).data, IPv4.from_data(info).data)
        with self.assertRaisesRegex(ProtocolError, 'IPv4: version=6 names another member'):
            IPv4.from_data(info, version=6)

    def test_a_subclass_outside_the_members_has_no_version(self) -> 'None':
        """A subclass of the base, not of a member, is built as itself without ``version``."""
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError

        for base, version in ((IP, 4), (ICMP, 6), (LinuxSLL, 1), (HTTP, 2)):
            with self.subTest(base=base.__name__):
                outside = type('Outside', (base,), {})
                self.assertIs(outside._construction_member({}), outside)  # pylint: disable=protected-access
                with self.assertRaisesRegex(ProtocolError, 'Outside: no version of its own'):
                    outside._construction_member({'version': version})  # pylint: disable=protected-access


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FromDataTests(unittest.TestCase):
    """``from_data`` rebuilds through the same path, and takes ``context`` by name."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_data_is_positional_and_context_by_name(self) -> 'None':
        """On the base and on every class overriding it."""
        import pcapkit.protocols.application.http.protocol as http
        import pcapkit.protocols.internet.ip.protocol as ip
        import pcapkit.protocols.link.link as link
        import pcapkit.protocols.protocol as protocol

        params = inspect.signature(protocol.ProtocolBase.from_data).parameters
        self.assertIs(params['data'].kind, inspect.Parameter.POSITIONAL_ONLY)
        self.assertIs(params['context'].kind, inspect.Parameter.KEYWORD_ONLY)
        for cls in (http.HTTP, ip.IP, link.Link):
            with self.subTest(cls=cls.__name__):
                self.assertIs(inspect.signature(cls.from_data).parameters['data'].kind,
                              inspect.Parameter.POSITIONAL_ONLY)

    def test_the_context_reaches_the_rebuild(self) -> 'None':
        """``context`` is adopted, and the old ``__context__`` and the stops are refused."""
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import UnexpectedKeyword

        info = TCP.from_fields(**TCP_FIELDS).info
        registry = ContextRegistry()
        rebuilt = TCP.from_data(info, context=registry)
        self.assertIs(rebuilt._exctx, registry)  # pylint: disable=protected-access
        self.assertEqual(rebuilt.data, TCP.from_fields(**TCP_FIELDS).data)
        for key in ('__context__', '_layer', '_protocol'):
            with self.subTest(key=key):
                with self.assertRaisesRegex(UnexpectedKeyword, repr(key)):
                    TCP.from_data(info, **{key: None})

    def test_a_generated_keyword_warns_and_never_raises(self) -> 'None':
        """A key ``_make_data`` gives that no signature declares is warned about."""
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.warnings import UnknownFieldWarning

        class Mismatched(TCP):
            @classmethod
            def _make_data(cls, data: 'Any') -> 'dict[str, Any]':
                return {**super()._make_data(data), 'no_such_field': 1}

        info = TCP.from_fields(**TCP_FIELDS).info
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = Mismatched.from_data(info)
        self.assertIs(type(rebuilt), Mismatched)
        self.assertEqual(rebuilt.data, TCP.from_fields(**TCP_FIELDS).data)
        messages = [str(item.message) for item in caught if isinstance(item.message, UnknownFieldWarning)]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn("'no_such_field'", messages[0])

    def test_the_default_make_data_leaves_an_undeclared_packet_out(self) -> 'None':
        """``packet``, which every parsed ``_info`` carries, is a field only where declared."""
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload
        from pcapkit.protocols.misc.raw.protocol import Raw

        empty = NoPayload.from_fields()
        self.assertIn('packet', empty.info.to_dict())
        self.assertNotIn('packet', NoPayload._make_data(empty.info))  # pylint: disable=protected-access

        raw = Raw(io.BytesIO(b'ab'), 2)
        self.assertIn('packet', Raw._make_data(raw.info))  # pylint: disable=protected-access
        self.assertEqual(Raw.from_data(raw.info).data, b'ab')

    def test_the_keyword_set_reads_no_init_and_no_parse_input(self) -> 'None':
        """``__init__`` is no consumer, and ``file``, ``length`` and the stops are no keyword."""
        from pcapkit.protocols.protocol import _KEYWORD_CONSUMERS, _declared_keywords
        from pcapkit.protocols.transport.tcp.protocol import TCP

        self.assertNotIn('__init__', _KEYWORD_CONSUMERS)
        declared = _declared_keywords(TCP)
        self.assertIsNotNone(declared)
        self.assertFalse({'file', 'length', 'layer', '_layer', '_protocol', '__context__',
                          'packet'} & set(declared or ()))
        self.assertIn('__packet__', declared or ())


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NoLegacyKeywordTests(unittest.TestCase):
    """The keywords ``Proto(**fields)`` took beyond the fields are gone (#2840)."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_out_of_band_keywords_are_refused(self) -> 'None':
        """The class call refuses them as unknown construction keywords, as ``from_fields`` does (#3081)."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import UnexpectedKeyword

        for key, value in (('_layer', 'Internet'), ('_protocol', 'tcp'), ('__context__', None),
                           ('packet', b'dropped')):
            with self.subTest(key=key), self.assertRaisesRegex(
                    UnexpectedKeyword, f"^TCP: unexpected keyword\\(s\\): '{key}'"):
                TCP(**TCP_FIELDS, **{key: value})

        with self.assertRaisesRegex(TypeError, r"^IPv4: nothing to parse; build one with IPv4\.from_fields\(\)$"):
            IPv4(None, version=4)

    def test_from_fields_and_from_data_suggest_context(self) -> 'None':
        """The context keyword they take is the one a misspelling is pointed to."""
        from pcapkit.protocols.transport.udp.protocol import UDP
        from pcapkit.utilities.exceptions import UnexpectedKeyword

        info = UDP.from_fields().info
        cases = (
            (lambda: UDP.from_fields(__context__=None), '__context__', 'context'),
            (lambda: UDP.from_fields(contxt=1), 'contxt', 'context'),
            (lambda: UDP.from_data(info, __context__=None), '__context__', 'context'),
        )
        for build, key, meant in cases:
            with self.subTest(key=key, meant=meant):
                with self.assertRaises(UnexpectedKeyword) as caught:
                    build()
                self.assertEqual(str(caught.exception),
                                 f'UDP: unexpected keyword(s): {key!r} (did you mean {meant!r}?)')

    def test_no_legacy_keyword_set_is_left(self) -> 'None':
        """``OUT_OF_BAND_KEYWORDS`` and ``_legacy_keywords`` go, and ``legacy`` with them."""
        import pcapkit.protocols.protocol as module

        self.assertFalse(hasattr(module, 'OUT_OF_BAND_KEYWORDS'))
        self.assertFalse(hasattr(module, '_legacy_keywords'))
        self.assertNotIn('legacy', inspect.signature(module._check_construction_keywords).parameters)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
