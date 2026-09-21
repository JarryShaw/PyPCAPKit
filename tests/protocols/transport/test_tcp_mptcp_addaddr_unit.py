# -*- coding: utf-8 -*-
"""``TCP._make_mptcp_addaddr`` builds an ``ADD_ADDR`` option that packs. GitHub issue #541.

Filed measurement: ``t._make_mptcp_addaddr(MPTCPOption.ADD_ADDR, addr_id=1, addr='1.2.3.4')``
warned ``UnknownFieldWarning`` twice -- once for ``kind``, once for ``length`` -- then
constructed a schema whose ``.pack()`` raised ``KeyError: 'length'`` from the ``port``
field's condition at (what was then) ``pcapkit/protocols/schema/transport/tcp.py:792``:

.. code-block:: python

    port: 'int' = ConditionalField(
        UInt16Field(),
        lambda pkt: pkt['length'] in (10, 22),
    )

Root cause: :class:`~pcapkit.protocols.schema.transport.tcp.MPTCP`, the base class every
Multipath TCP subtype schema inherits, declared ``kind`` and ``length`` only under
:data:`~typing.TYPE_CHECKING` -- annotations for a type checker, not real
:class:`~pcapkit.corekit.fields.field.FieldBase` descriptors. So ``Schema.__update__``
rejected both keyword arguments as unknown and dropped them, and by the time ``pack()``
reached ``port``'s lambda, ``length`` was never in the packet mapping at all. The ``port``
predicate reading ``pkt['length']`` is not an independent circularity: ``length`` is
supplied by the caller (the arithmetic differs by IP version and by whether ``port`` is
given, but it does not depend on ``port`` having already been packed), so once ``length``
is a real field that lands before ``port`` in field order, the predicate reads a value
that is already there. Fixed by declaring real ``kind``/``length`` fields on ``MPTCP``
itself, mirroring how :class:`~pcapkit.protocols.schema.transport.tcp.Option` already
does it for every non-Multipath TCP option -- see ``MPTCP`` in
:mod:`pcapkit.protocols.schema.transport.tcp`.

That one change also fixes construction for every other ``_make_mptcp_*`` helper in
:mod:`pcapkit.protocols.transport.tcp` that passes ``kind=``/``length=`` to its schema
the same way (``_make_mptcp_unknown``, ``_make_mptcp_capable``, ``_make_join_syn``,
``_make_join_synack``, ``_make_join_ack``, ``_make_mptcp_dss``, ``_make_mptcp_remove``,
``_make_mptcp_prio``, ``_make_mptcp_fail`` and ``_make_mptcp_fastclose``, alongside
``_make_mptcp_addaddr`` itself -- eleven in total), but this module only covers
``ADD_ADDR``, the case the issue was filed against. It asserts on packed bytes, not
merely on successful construction, since construction already succeeded before this fix
and only ``pack()`` failed.

The same missing fields broke *unpacking*, not only packing, and for the identical
reason: with no real ``kind``/``length`` fields on the base class, ``MPTCPAddAddress``'s
own leading field (``test``, the subtype/IP-version octet) started reading one octet too
early -- the ``kind`` octet itself (``0x1e``) -- rather than the third octet of the
option. That is an off-by-two in field alignment, not a wire-format change: the octets a
correct sender already puts on the wire were always right, only this library's reading of
them was shifted. Measured on the pre-fix code with the hand-built, spec-correct wire
octets :data:`ADD_ADDR_SPEC_OCTETS` and :data:`MP_PRIO_SPEC_OCTETS` below (neither built
through any ``_make_mptcp_*`` maker, so the pack and parse directions cannot cancel each
other's bug out): ``0x1e`` decoded as subtype ``1``/version ``14``, an IP version nothing
accepts, so :class:`TCPMPTCPUnpackUnitTests.test_add_addr_spec_octets_parse_correctly`
raised ``FieldError: TCP: [OptNo 30] 3 invalid IP version`` before this fix; MP_PRIO has
no such guard, so :class:`TCPMPTCPUnpackUnitTests.test_mp_prio_spec_octets_parse_correctly`
instead ran the misaligned bytes as far as ``MPTCPPriority.addr_id``'s own
``pkt['length']``-gated :class:`~pcapkit.corekit.fields.misc.ConditionalField` and raised
``KeyError: 'length'`` -- the same exception #541 was filed against, reached from the
opposite direction. Both parse correctly after this fix, every field exactly as the
octets were built.

"""
from __future__ import annotations

import unittest
import warnings

from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.utilities.warnings import UnknownFieldWarning

#: A spec-correct ``ADD_ADDR`` option, RFC 8684 section 3.4.1: ``Kind`` ``0x1e``
#: (Multipath TCP), ``Length`` ``8``, ``Subtype`` ``3``/``IPVer`` ``4`` packed into one
#: octet as ``0x34``, ``Address ID`` ``1``, then the four octets of ``192.0.2.1``. Built
#: by hand from the RFC figure, not through :meth:`TCP._make_mptcp_addaddr
#: <pcapkit.protocols.transport.tcp.TCP._make_mptcp_addaddr>` or any other maker, so a
#: symmetric pack/parse bug could not cancel itself out here.
ADD_ADDR_SPEC_OCTETS = bytes([0x1E, 0x08, 0x34, 0x01, 0xC0, 0x00, 0x02, 0x01])

#: A spec-correct ``MP_PRIO`` option carrying the optional ``Address ID``, RFC 8684
#: section 3.3.8: ``Kind`` ``0x1e``, ``Length`` ``4``, ``Subtype`` ``5`` with the backup
#: (``B``) flag set packed into one octet as ``0x51``, ``Address ID`` ``5``. Likewise
#: hand-built rather than made.
MP_PRIO_SPEC_OCTETS = bytes([0x1E, 0x04, 0x51, 0x05])


def build_tcp_segment(option_octets: 'bytes') -> 'bytes':
    """Pack a whole TCP segment carrying ``option_octets`` verbatim as its only option.

    Goes through :class:`~pcapkit.protocols.schema.transport.tcp.TCP` (the schema, not
    the protocol) directly, supplying ``option_octets`` to the ``options`` field as raw
    bytes -- which :class:`~pcapkit.corekit.fields.collections.OptionField` packs
    unchanged -- so nothing here calls a ``_make_mptcp_*`` maker. Everything but the
    option itself (ports, sequence numbers, flags, the data offset computed from
    ``option_octets``' own length) is unrelated to the Multipath TCP defect under test.

    Args:
        option_octets: The whole option, header octets included, already padded to a
            multiple of 4 octets (both :data:`ADD_ADDR_SPEC_OCTETS` and
            :data:`MP_PRIO_SPEC_OCTETS` are).

    Returns:
        The packed TCP segment.

    """
    if len(option_octets) % 4:
        raise ValueError('option_octets must already be a multiple of 4 octets long')

    schema = Schema_TCP(
        srcport=50000, dstport=80, seq=1, ack=0,
        offset={'offset': 5 + len(option_octets) // 4, 'ns': 0},
        flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': 0, 'psh': 0, 'rst': 0, 'syn': 1, 'fin': 0},
        window=8192, checksum=b'\x00\x00', urgent=0,
        options=option_octets,
        payload=b'',
    )
    return schema.pack()


def make_addaddr(**kwargs: 'object') -> 'bytes':
    """Build an ``ADD_ADDR`` option through the maker under test and pack it.

    Args:
        **kwargs: forwarded to :meth:`TCP._make_mptcp_addaddr
            <pcapkit.protocols.transport.tcp.TCP._make_mptcp_addaddr>`.

    Returns:
        The packed option bytes.

    """
    tcp = TCP.__new__(TCP)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        schema = tcp._make_mptcp_addaddr(Enum_MPTCPOption.ADD_ADDR, **kwargs)  # pylint: disable=protected-access
    unknown_field_warnings = [w for w in caught if issubclass(w.category, UnknownFieldWarning)]
    if unknown_field_warnings:
        raise AssertionError(
            f'unexpected UnknownFieldWarning(s): {[str(w.message) for w in unknown_field_warnings]}')
    return schema.pack()


class TCPMPTCPAddAddressUnitTests(unittest.TestCase):
    """``ADD_ADDR`` constructs *and* packs, for both IP versions and both port cases."""

    def test_ipv4_without_port(self) -> None:
        """``kind=0x1e length=8 test=0x34 addr_id=1 address=1.2.3.4``, no ``port`` octets.

        Length is ``4 + 4 + 0 == 8``, one of the two values (with 22) the ``port``
        field's own condition never selects, so no port octets are packed.

        """
        packed = make_addaddr(addr_id=1, addr='1.2.3.4')

        self.assertEqual(packed, bytes.fromhex('1e08340101020304'))
        self.assertEqual(len(packed), 8)
        self.assertEqual(packed[1], 8, 'the packed length octet must match the wire length')

    def test_ipv4_with_port(self) -> None:
        """``length=10`` (``4 + 4 + 2``) and the port octets ``01bb`` (443) are appended.

        10 is one of the two values the predicate ``pkt['length'] in (10, 22)`` selects
        for, so this is the IPv4 case where ``port`` actually packs.

        """
        packed = make_addaddr(addr_id=1, addr='1.2.3.4', port=443)

        self.assertEqual(packed, bytes.fromhex('1e0a34010102030401bb'))
        self.assertEqual(len(packed), 10)
        self.assertEqual(packed[-2:], bytes.fromhex('01bb'))

    def test_ipv6_without_port(self) -> None:
        """``length=20`` (``4 + 16``) for a bare IPv6 address, no ``port`` octets."""
        packed = make_addaddr(addr_id=2, addr='::1')

        self.assertEqual(
            packed, bytes.fromhex('1e14360200000000000000000000000000000001'))
        self.assertEqual(len(packed), 20)
        self.assertEqual(packed[1], 20)

    def test_ipv6_with_port(self) -> None:
        """``length=22`` (``4 + 16 + 2``), the second value the predicate selects for."""
        packed = make_addaddr(addr_id=2, addr='::1', port=443)

        self.assertEqual(
            packed, bytes.fromhex('1e1636020000000000000000000000000000000101bb'))
        self.assertEqual(len(packed), 22)
        self.assertEqual(packed[-2:], bytes.fromhex('01bb'))

    def test_opt_argument_round_trips_through_the_maker(self) -> None:
        """Passing a previously-parsed ``opt`` takes the same path as the keyword form.

        ``_make_mptcp_addaddr`` reads ``addr_id``/``addr``/``port`` off ``opt`` instead of
        the keyword arguments when one is given, so this exercises that branch against the
        same assertion as :meth:`test_ipv4_with_port`.

        """
        import ipaddress

        from pcapkit.protocols.data.transport.tcp import MPTCPAddAddress as Data_MPTCPAddAddress
        from pcapkit.const.tcp.option import Option as Enum_Option

        # NOTE: ``opt.addr`` has to already be an ``IPv4Address``/``IPv6Address``, as it
        # would be coming from a real ``_read_mptcp_addaddr`` result (``schema.address``,
        # parsed through ``IPv4AddressField``/``IPv6AddressField``) -- the ``opt is not
        # None`` branch below reads ``opt.addr`` straight into ``addr_val`` and skips
        # ``parse_ip_address`` entirely, unlike the keyword-argument branch.
        opt = Data_MPTCPAddAddress(
            kind=Enum_Option.Multipath_TCP,
            length=10,
            subtype=Enum_MPTCPOption.ADD_ADDR,
            version=4,
            addr_id=1,
            addr=ipaddress.ip_address('1.2.3.4'),
            port=443,
        )

        tcp = TCP.__new__(TCP)
        schema = tcp._make_mptcp_addaddr(Enum_MPTCPOption.ADD_ADDR, opt)  # pylint: disable=protected-access
        packed = schema.pack()

        self.assertEqual(packed, bytes.fromhex('1e0a34010102030401bb'))


class TCPMPTCPUnpackUnitTests(unittest.TestCase):
    """Spec-correct MPTCP option octets parse into a :class:`TCP`, field by field.

    Every case above builds an option and packs it; none of them ever asks the library
    to *parse* one, so the identical off-by-two that broke packing -- ``MPTCPAddAddress``
    (and its siblings) reading the ``kind`` octet as their own first field, because
    ``MPTCP`` supplied no real ``kind``/``length`` fields for anything ahead of it to
    consume -- shipped unpinned on the read side. These two do not construct anything
    through a maker at all: :data:`ADD_ADDR_SPEC_OCTETS` and :data:`MP_PRIO_SPEC_OCTETS`
    are hand-built from the RFC 8684 figures, spliced into a real TCP segment by
    :func:`build_tcp_segment`, and parsed back through :class:`TCP` proper.

    """

    def test_add_addr_spec_octets_parse_correctly(self) -> None:
        """RFC 8684 section 3.4.1's IPv4 ``ADD_ADDR``, addr_id=1, 192.0.2.1.

        Pre-fix this raised ``FieldError: TCP: [OptNo 30] 3 invalid IP version`` --
        ``MPTCPAddAddress.test`` read the ``kind`` octet ``0x1e`` (``0001 1110``) as its
        own subtype/version octet, decoding ``version=14``, which
        :func:`~pcapkit.protocols.schema.transport.tcp.mptcp_add_address_selector`
        rejects outright since it is neither 4 nor 6.

        """
        from pcapkit.const.tcp.option import Option as Enum_Option

        raw = build_tcp_segment(ADD_ADDR_SPEC_OCTETS)
        tcp = TCP(raw, len(raw))
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.kind, Enum_Option.Multipath_TCP)
        self.assertEqual(data.length, 8)
        self.assertEqual(data.subtype, Enum_MPTCPOption.ADD_ADDR)
        self.assertEqual(data.version, 4)
        self.assertEqual(data.addr_id, 1)
        self.assertEqual(str(data.addr), '192.0.2.1')
        self.assertIsNone(data.port)

    def test_mp_prio_spec_octets_parse_correctly(self) -> None:
        """RFC 8684 section 3.3.8's ``MP_PRIO`` with the optional Address ID, backup set.

        Pre-fix this raised ``KeyError: 'length'``: ``MP_PRIO`` carries no IP-version
        guard the way ``ADD_ADDR`` does, so the same off-by-two misalignment ran on
        through to ``MPTCPPriority.addr_id``'s own
        ``ConditionalField(UInt8Field(), lambda pkt: pkt['length'] == 4)`` -- the same
        exception #541 was filed against, reached by parsing rather than by packing.

        """
        from pcapkit.const.tcp.option import Option as Enum_Option

        raw = build_tcp_segment(MP_PRIO_SPEC_OCTETS)
        tcp = TCP(raw, len(raw))
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.kind, Enum_Option.Multipath_TCP)
        self.assertEqual(data.length, 4)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_PRIO)
        self.assertTrue(data.backup)
        self.assertEqual(data.addr_id, 5)


if __name__ == '__main__':
    unittest.main()
