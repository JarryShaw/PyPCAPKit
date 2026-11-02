# -*- coding: utf-8 -*-
"""A protocol's ``__index__`` is its LinkType, EtherType, TransType or AppType value (#2627).

The owner ruled on #2627 that ``__index__`` returns the protocol's member of one of
those registries wherever one names it, ahead of any other registry's code such as
an ARPHRD type, bar the classes in :data:`EXCEPTIONS`. An AppType member is a
:class:`str`, which ``__index__`` may not return, so an AppType-valued index is
the member's port as an :class:`int`. :data:`EXPECTED` derives each class's value
from the registry and the number it assigns, never from ``__index__``, and the
tests hold every protocol class to the rule in both directions: a class in the
table returns that value, and a class returning a member of one of those
registries is in the table. A class in neither table returns :data:`None` or
raises.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import importlib
import importlib.util
import operator
import pkgutil
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a sweep over every protocol class, under its index.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

LINKTYPE = 'pcapkit.const.reg.linktype.LinkType'
ETHERTYPE = 'pcapkit.const.reg.ethertype.EtherType'
TRANSTYPE = 'pcapkit.const.reg.transtype.TransType'
APP_TCP = 'pcapkit.const.reg.apptype.tcp.TCP'
APP_UDP = 'pcapkit.const.reg.apptype.udp.UDP'
APP_SCTP = 'pcapkit.const.reg.apptype.sctp.SCTP'
ARPHRD = 'pcapkit.const.linux.arphrd.ARPHRD'

#: The AppType registries, whose member a class's index gives as its port.
APPTYPES = (APP_TCP, APP_UDP, APP_SCTP)

#: Every protocol class one of those registries names, as ``class: (registry,
#: number)``: tcpdump.org's LINKTYPE value, IEEE's EtherType, IANA's protocol
#: number, or the IANA port the class is bound at.
EXPECTED = {
    'pcapkit.protocols.application.drarp.DRARP': (ETHERTYPE, 0x8035),
    'pcapkit.protocols.application.dtls.DTLS': (APP_UDP, 5684),
    'pcapkit.protocols.application.ftp.FTP': (APP_TCP, 21),
    'pcapkit.protocols.application.ftp_data.FTP_DATA': (APP_TCP, 20),
    'pcapkit.protocols.application.http.HTTP': (APP_TCP, 80),
    'pcapkit.protocols.application.httpv1.HTTPv1': (APP_TCP, 80),
    'pcapkit.protocols.application.httpv2.HTTPv2': (APP_TCP, 80),
    'pcapkit.protocols.application.ngap.NGAP': (APP_SCTP, 38412),
    'pcapkit.protocols.application.ospf.OSPF': (TRANSTYPE, 89),
    'pcapkit.protocols.application.rarp.RARP': (ETHERTYPE, 0x8035),
    'pcapkit.protocols.application.sslv3.SSLv3': (APP_TCP, 443),
    'pcapkit.protocols.application.tls.TLS': (APP_TCP, 443),
    'pcapkit.protocols.internet.ah.AH': (TRANSTYPE, 51),
    'pcapkit.protocols.internet.esp.ESP': (TRANSTYPE, 50),
    'pcapkit.protocols.internet.hip.HIP': (TRANSTYPE, 139),
    'pcapkit.protocols.internet.hopopt.HOPOPT': (TRANSTYPE, 0),
    'pcapkit.protocols.internet.icmpv4.ICMPv4': (TRANSTYPE, 1),
    'pcapkit.protocols.internet.icmpv6.ICMPv6': (TRANSTYPE, 58),
    'pcapkit.protocols.internet.igmp.IGMP': (TRANSTYPE, 2),
    'pcapkit.protocols.internet.igmpv1.IGMPv1': (TRANSTYPE, 2),
    'pcapkit.protocols.internet.igmpv2.IGMPv2': (TRANSTYPE, 2),
    'pcapkit.protocols.internet.igmpv3.IGMPv3': (TRANSTYPE, 2),
    'pcapkit.protocols.internet.ipv4.IPv4': (TRANSTYPE, 4),
    'pcapkit.protocols.internet.ipv6.IPv6': (TRANSTYPE, 41),
    'pcapkit.protocols.internet.ipv6_frag.IPv6_Frag': (TRANSTYPE, 44),
    'pcapkit.protocols.internet.ipv6_opts.IPv6_Opts': (TRANSTYPE, 60),
    'pcapkit.protocols.internet.ipv6_route.IPv6_Route': (TRANSTYPE, 43),
    'pcapkit.protocols.internet.ipx.IPX': (TRANSTYPE, 111),
    'pcapkit.protocols.internet.mh.MH': (TRANSTYPE, 135),
    'pcapkit.protocols.link.arp.ARP': (ETHERTYPE, 0x0806),
    'pcapkit.protocols.link.c_tag.C_Tag': (ETHERTYPE, 0x8100),
    'pcapkit.protocols.link.ethernet.Ethernet': (LINKTYPE, 1),
    'pcapkit.protocols.link.frad.FRAD': (LINKTYPE, 107),
    'pcapkit.protocols.link.gre.GRE': (TRANSTYPE, 47),
    'pcapkit.protocols.link.ieee802_11.IEEE802_11': (LINKTYPE, 105),
    'pcapkit.protocols.link.inarp.InARP': (ETHERTYPE, 0x0806),
    'pcapkit.protocols.link.l2tpv2.L2TPv2': (APP_UDP, 1701),
    'pcapkit.protocols.link.linux_sll1.LinuxSLL1': (LINKTYPE, 113),
    'pcapkit.protocols.link.linux_sll2.LinuxSLL2': (LINKTYPE, 276),
    'pcapkit.protocols.link.loopback.Loopback': (LINKTYPE, 0),
    'pcapkit.protocols.link.radiotap.Radiotap': (LINKTYPE, 127),
    'pcapkit.protocols.link.s_tag.S_Tag': (ETHERTYPE, 0x88A8),
    'pcapkit.protocols.transport.dccp.DCCP': (TRANSTYPE, 33),
    'pcapkit.protocols.transport.sctp.SCTP': (TRANSTYPE, 132),
    'pcapkit.protocols.transport.tcp.TCP': (TRANSTYPE, 6),
    'pcapkit.protocols.transport.udp.UDP': (TRANSTYPE, 17),
}

#: Classes that keep another registry's code, in the same form. Netlink keeps
#: ARPHRD_NETLINK, as LINKTYPE_NETLINK (253) names the SLL-framed form (#2627).
EXCEPTIONS = {
    'pcapkit.protocols.link.netlink.Netlink': (ARPHRD, 824),
}


def _load(path: 'str') -> 'Any':
    """The object a dotted ``module.Name`` path names."""
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


def _expected(path: 'str') -> 'Any':
    """The registry member :data:`EXPECTED` names for the class at ``path``."""
    registry, number = EXPECTED[path]
    return _load(registry).get(number)


def _protocols() -> 'list[type]':
    """Every :class:`~pcapkit.protocols.protocol.ProtocolBase` descendant, sorted."""
    import pcapkit.protocols as protopkg
    from pcapkit.protocols.protocol import ProtocolBase

    # Import every protocol module, or ``__subclasses__`` sees only whatever this
    # process happened to touch first.
    for info in pkgutil.walk_packages(protopkg.__path__, prefix='pcapkit.protocols.'):
        importlib.import_module(info.name)

    found = set()  # type: set[type]
    stack = [ProtocolBase]  # type: list[type]
    while stack:
        for sub in stack.pop().__subclasses__():
            if sub not in found:
                found.add(sub)
                stack.append(sub)
    return sorted(found, key=lambda cls: (cls.__module__, cls.__qualname__))


def _index(cls: 'Any') -> 'Any':
    """``cls.__index__()``, or the exception it raises."""
    try:
        return cls.__index__()
    except Exception as exc:  # pylint: disable=broad-except
        return exc


def _instances() -> 'dict[str, Any]':
    """An instance of each AppType-valued class in :data:`EXPECTED`, by its path."""
    from pcapkit.const.http.frame import Frame
    from pcapkit.protocols.application.dtls import DTLS
    from pcapkit.protocols.application.ftp import FTP
    from pcapkit.protocols.application.ftp_data import FTP_DATA
    from pcapkit.protocols.application.http import HTTP
    from pcapkit.protocols.application.httpv1 import HTTPv1
    from pcapkit.protocols.application.httpv2 import HTTPv2
    from pcapkit.protocols.application.ngap import NGAP
    from pcapkit.protocols.application.sslv3 import SSLv3
    from pcapkit.protocols.application.tls import TLS
    from pcapkit.protocols.link.l2tpv2 import L2TPv2

    # a ChangeCipherSpec record of each, under legacy version 0x0303, 0x0300 and 0xFEFD
    tls, sslv3 = b'\x14\x03\x03\x00\x01\x01', b'\x14\x03\x00\x00\x01\x01'
    dtls = b'\x14\xfe\xfd\x00\x00' + (1).to_bytes(6, 'big') + b'\x00\x01\x01'

    return {
        'pcapkit.protocols.application.dtls.DTLS': DTLS(dtls),
        'pcapkit.protocols.application.ftp.FTP': FTP(b'USER anonymous\r\n'),
        'pcapkit.protocols.application.ftp_data.FTP_DATA': FTP_DATA(b'abc'),
        'pcapkit.protocols.application.http.HTTP': HTTP(b'GET / HTTP/1.1\r\n\r\n'),
        'pcapkit.protocols.application.httpv1.HTTPv1': HTTPv1(method='GET', uri='/',
                                                              http_version='1.1'),
        'pcapkit.protocols.application.httpv2.HTTPv2': HTTPv2(type=Frame.DATA, sid=1,
                                                              frame={'data': b'x'}),
        # unparsed, since decoding NGAP needs the optional pycrate
        'pcapkit.protocols.application.ngap.NGAP': object.__new__(NGAP),
        'pcapkit.protocols.application.sslv3.SSLv3': SSLv3(sslv3),
        'pcapkit.protocols.application.tls.TLS': TLS(tls),
        'pcapkit.protocols.link.l2tpv2.L2TPv2': L2TPv2(version=2, tunnel_id=1, session_id=2),
    }


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolIndexRegistryTests(unittest.TestCase):
    """Every protocol class's index is its own standard registry value."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _standard(self) -> 'tuple[type, ...]':
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType

        return (LinkType, EtherType, TransType, AppType)

    def test_each_class_returns_the_value_its_registry_assigns(self) -> None:
        for path, (registry, number) in EXPECTED.items():
            with self.subTest(protocol=path):
                member = _expected(path)
                self.assertEqual(int(member), number)
                if registry in APPTYPES:
                    self.assertIs(type(_index(_load(path))), int)
                    self.assertEqual(_index(_load(path)), number)
                else:
                    self.assertIs(_index(_load(path)), member)

    def test_each_exception_returns_its_own_registrys_member(self) -> None:
        for path, (registry, number) in EXCEPTIONS.items():
            with self.subTest(protocol=path):
                member = _load(registry).get(number)
                self.assertEqual(int(member), number)
                self.assertIs(_index(_load(path)), member)

    def test_int_and_operator_index_give_an_apptype_valued_instances_port(self) -> None:
        instances = _instances()
        self.assertEqual(sorted(instances),
                         sorted(path for path, (registry, _) in EXPECTED.items()
                                if registry in APPTYPES))
        for path, instance in instances.items():
            with self.subTest(protocol=path):
                self.assertIsInstance(instance, _load(path))
                self.assertEqual(int(instance), EXPECTED[path][1])
                self.assertEqual(operator.index(instance), EXPECTED[path][1])

    def test_every_class_returning_a_standard_value_is_in_the_table(self) -> None:
        standard = self._standard()
        stray = [f'{cls.__module__}.{cls.__qualname__}' for cls in _protocols()
                 if isinstance(_index(cls), standard)
                 and f'{cls.__module__}.{cls.__qualname__}' not in EXPECTED]
        self.assertEqual(stray, [])

    def test_no_class_returns_another_registrys_code(self) -> None:
        """Outside both tables an index is :data:`None` or raises, never an
        ARPHRD type, NLPID or other secondary code.
        """
        standard = self._standard()
        other = {f'{cls.__module__}.{cls.__qualname__}': repr(value) for cls in _protocols()
                 if f'{cls.__module__}.{cls.__qualname__}' not in {**EXPECTED, **EXCEPTIONS}
                 for value in (_index(cls),)
                 if not (value is None or isinstance(value, (Exception,) + standard))}
        self.assertEqual(other, {})

    def test_a_member_sharing_its_bases_value_inherits_it(self) -> None:
        """A family member whose value is its base's defines no ``__index__``."""
        for path, value in EXPECTED.items():
            cls = _load(path)
            for base in cls.__mro__[1:]:
                name = f'{base.__module__}.{base.__qualname__}'
                if EXPECTED.get(name) == value:
                    with self.subTest(protocol=path, base=name):
                        self.assertNotIn('__index__', vars(cls))
                    break


if __name__ == '__main__':
    unittest.main()
