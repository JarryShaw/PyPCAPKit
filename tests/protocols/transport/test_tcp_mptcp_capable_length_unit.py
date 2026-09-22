# -*- coding: utf-8 -*-
"""MP_CAPABLE's length and its receiver's-key predicate agreed on neither RFC 8684 form.

GitHub issue #567, found while fixing #541 and widened during #565's cross-review.

Two independent defects, and both had to move together
--------------------------------------------------------

:rfc:`8684` section 3.1 gives ``MP_CAPABLE`` as **12** octets without the receiver's key and
**20** octets with it.

``TCP._make_mptcp_capable`` (``pcapkit/protocols/transport/tcp.py``) wrote
``length=20 if rkey is None else 32`` -- both branches wrong, and the no-key branch writing
the value RFC 8684 assigns to the *other* case.

Independently, ``MPTCPCapable.rkey`` (``pcapkit/protocols/schema/transport/tcp.py``) was

.. code-block:: python

    rkey: 'int' = ConditionalField(
        UInt64Field(),
        lambda pkt: pkt['length'] != 32,
    )

-- the receiver's key field packed for every length *except* 32, i.e. dropped for exactly the
length the (also wrong) maker used to signal "key present". Fixing only the maker would have
made a 20-octet, key-present option fail this predicate (``20 != 32`` is true, so the field
would misfire as present regardless -- but a *correct* 12-octet, key-absent option satisfies
``12 != 32`` too, so the key field would still pack, appending 8 phantom octets). Fixing only
the predicate without the maker would leave both of the maker's wrong lengths (20, 32) on the
wire. Neither half alone closes the gap; both are fixed in the same change here, to
``length=12 if rkey is None else 20`` and ``lambda pkt: pkt['length'] == 20`` respectively.

A third site shared the same wrong constants and would otherwise have re-broken this the
moment #566 let construction reach it: ``TCP._read_mptcp_capable`` rejected anything but
``schema.length in (20, 32)``, and read ``rkey`` only ``if schema.length == 32``. Fixed
alongside the other two, to ``(12, 20)`` and ``== 20``.

Filed measurement, pre-fix (all three sites still at the old constants): a maker call with
``rkey=None`` packed a *20*-octet option (the value RFC 8684 assigns to the with-key form)
carrying no key octets, and a maker call with an explicit ``rkey`` packed a *32*-octet option
whose last 12 octets are entirely unaccounted for by the RFC 8684 figure.

Coverage
--------

Byte-exact packed assertions for both RFC-defined forms -- 12 octets without the receiver's
key, 20 with it -- rather than asserting either component (the maker's arithmetic, or the
schema's predicate) in isolation, per the pattern #565 established for ``ADD_ADDR``: this
module also splices hand-built, spec-correct octets into a full segment via
``Schema_TCP(options=..., ...)``, bypassing the makers entirely, so the *parse* direction is
pinned independently of whatever the *pack* direction happens to produce.

"""
from __future__ import annotations

import unittest

#: A spec-correct MP_CAPABLE without the receiver's key, RFC 8684 figure 4: ``Kind`` ``0x1e``,
#: ``Length`` ``12``, ``Subtype`` ``0`` (MP_CAPABLE)/``Version`` ``1`` packed into ``0x01``,
#: flag octet ``0x81``, then the sender's key, 8 octets of ``0xAA``. Hand-built, not made, so a
#: symmetric pack/parse bug could not cancel itself out here -- the same octets
#: :data:`tests.protocols.transport.test_tcp_mptcp_length_unit.MP_CAPABLE_OPTION` uses for the
#: header-offset regression, extended here to a full parse.
MP_CAPABLE_NO_KEY_SPEC_OCTETS = bytes([0x1E, 0x0C, 0x01, 0x81]) + b'\xAA' * 8

#: The same option, with the receiver's key present: RFC 8684 figure 4's other conditional row
#: (there is one MP_CAPABLE figure, not two -- both length forms come from it), ``Length``
#: ``20``, the sender's key unchanged, and 8 octets of ``0xBB`` for the receiver's key.
MP_CAPABLE_WITH_KEY_SPEC_OCTETS = bytes([0x1E, 0x14, 0x01, 0x81]) + b'\xAA' * 8 + b'\xBB' * 8


def build_tcp_segment(option_octets: 'bytes') -> 'bytes':
    """Pack a whole TCP segment carrying ``option_octets`` verbatim as its only option.

    Goes through :class:`~pcapkit.protocols.schema.transport.tcp.TCP` (the schema, not the
    protocol) directly, supplying ``option_octets`` to the ``options`` field as raw bytes,
    which :class:`~pcapkit.corekit.fields.collections.OptionField` packs unchanged -- so
    nothing here calls a ``_make_mptcp_*`` maker.

    Args:
        option_octets: The whole option, header octets included, already padded to a multiple
            of 4 octets (both spec octets constants above are).

    Returns:
        The packed TCP segment.

    Note:
        ``Schema_TCP`` is imported here, inside the function, not at module level -- see
        :func:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.build_mptcp_option`'s
        own docstring for why: a name bound to ``pcapkit`` at collection time can go stale
        once another test module in this suite pops ``pcapkit``'s submodules out of
        ``sys.modules`` and a later import re-creates them.

    """
    from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP

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


def make_capable(**kwargs: 'object') -> 'bytes':
    """Build an MP_CAPABLE option through the maker under test and pack it.

    Args:
        **kwargs: forwarded to :meth:`TCP._make_mptcp_capable
            <pcapkit.protocols.transport.tcp.TCP._make_mptcp_capable>`.

    Returns:
        The packed option bytes.

    """
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    from pcapkit.protocols.transport.tcp import TCP

    tcp = TCP.__new__(TCP)
    schema = tcp._make_mptcp_capable(Enum_MPTCPOption.MP_CAPABLE, **kwargs)  # pylint: disable=protected-access
    return schema.pack()


class TCPMPTCPCapableMakerUnitTests(unittest.TestCase):
    """``_make_mptcp_capable`` packs the RFC 8684 length for each form."""

    def test_no_key_packs_twelve_octets(self) -> None:
        """``rkey=None`` packs 12 octets: RFC 8684 figure 4, the key-absent form.

        Pre-fix this packed **20** octets (the with-key value) and carried no key octets at
        all -- the maker's own ``length=20 if rkey is None else 32`` read backwards relative
        to RFC 8684.

        """
        packed = make_capable(skey=0x0102030405060708, rkey=None)

        self.assertEqual(len(packed), 12)
        self.assertEqual(packed[1], 12, 'the packed length octet must match the wire length')
        self.assertEqual(packed, bytes([0x1E, 0x0C, 0x00, 0x00]) + bytes.fromhex('0102030405060708'))

    def test_with_key_packs_twenty_octets(self) -> None:
        """An explicit ``rkey`` packs 20 octets: RFC 8684 figure 4, the key-present form.

        Pre-fix this packed **32** octets, the last 12 of which are unaccounted for by RFC
        8684 -- the maker wrote ``length=32``, and pre-#567's ``rkey`` predicate
        (``pkt['length'] != 32``) then *dropped* the key for this exact length, so those 12
        extra octets were not even the key it claimed to carry.

        """
        packed = make_capable(skey=0x0102030405060708, rkey=0x1112131415161718)

        self.assertEqual(len(packed), 20)
        self.assertEqual(packed[1], 20, 'the packed length octet must match the wire length')
        self.assertEqual(
            packed,
            bytes([0x1E, 0x14, 0x00, 0x00])
            + bytes.fromhex('0102030405060708')
            + bytes.fromhex('1112131415161718'),
        )

    def test_default_rkey_of_zero_is_still_the_with_key_form(self) -> None:
        """``rkey=0`` is a *present* key of value zero, not an absent one.

        ``_make_mptcp_capable``'s own default is ``rkey=0``, not ``None`` -- this is the case
        :func:`examples.generators.options.options` actually exercises for MP_CAPABLE, and it
        must produce the 20-octet form with an all-zero receiver's key on the wire, not the
        12-octet form.

        """
        packed = make_capable(skey=0x0102030405060708)

        self.assertEqual(len(packed), 20)
        self.assertEqual(packed[-8:], bytes(8))


class TCPMPTCPCapableParseUnitTests(unittest.TestCase):
    """Spec-correct MP_CAPABLE octets parse for both RFC 8684 forms.

    Neither case here is built through a maker; both are spliced, as raw bytes, into a real
    TCP segment and parsed back through :class:`TCP` proper -- so a pack-side bug and a
    parse-side bug could not cancel each other out and hide behind a passing round trip.

    """

    def test_no_key_spec_octets_parse_correctly(self) -> None:
        """RFC 8684 figure 4's 12-octet form parses, with ``rkey`` absent.

        Pre-#566/#567 this raised ``ProtocolError: TCP: [OptNo 30] invalid format`` from
        ``_read_mptcp_capable``'s ``schema.length not in (20, 32)`` guard -- 12 satisfied
        neither of the two (both wrong) accepted values.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(MP_CAPABLE_NO_KEY_SPEC_OCTETS)
        tcp = TCP(raw, len(raw))
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.kind, Enum_Option.Multipath_TCP)
        self.assertEqual(data.length, 12)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_CAPABLE)
        self.assertEqual(data.version, 1)
        self.assertEqual(data.skey, 0xAAAAAAAAAAAAAAAA)
        self.assertIsNone(data.rkey)

    def test_with_key_spec_octets_parse_correctly(self) -> None:
        """RFC 8684 figure 4's 20-octet form parses, with ``rkey`` present.

        Pre-#566/#567, ``schema.length not in (20, 32)`` did accept 20 -- but
        ``rkey=schema.rkey if schema.length == 32 else None`` then discarded it anyway, since
        20 is not 32, so the receiver's key silently vanished rather than being reported.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(MP_CAPABLE_WITH_KEY_SPEC_OCTETS)
        tcp = TCP(raw, len(raw))
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.kind, Enum_Option.Multipath_TCP)
        self.assertEqual(data.length, 20)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_CAPABLE)
        self.assertEqual(data.version, 1)
        self.assertEqual(data.skey, 0xAAAAAAAAAAAAAAAA)
        self.assertEqual(data.rkey, 0xBBBBBBBBBBBBBBBB)


class TCPMPTCPCapablePublicConstructorUnitTests(unittest.TestCase):
    """Both RFC 8684 forms round-trip through the public ``TCP`` convenience constructor."""

    #: Header fields shared by every constructed TCP segment in this class, matching
    #: :data:`examples.generators.options.TCP_BASE`.
    TCP_BASE = {
        'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
        'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
        'psh': False, 'rst': False, 'syn': True, 'fin': False,
        'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
        'payload': b'',
    }

    def test_no_key_round_trip_is_twelve_octets(self) -> None:
        """``rkey=None`` through ``TCP()`` packs a 12-octet option and reports no ``rkey``."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.MP_CAPABLE,
                'skey': 0x0102030405060708,
                'rkey': None,
            })],
            **self.TCP_BASE,  # type: ignore[arg-type]
        )
        data = tcp.info.options[Enum_Option.Multipath_TCP]
        packed = bytes(tcp)

        self.assertEqual(data.length, 12)
        self.assertIsNone(data.rkey)
        # NOTE: the option is the only thing in the segment's payload-free options list, so it
        # is the last 12 octets of the packed segment -- the fixed 20-octet TCP header plus
        # this option is the whole packet.
        self.assertEqual(packed[-12:], bytes([0x1E, 0x0C, 0x00, 0x00]) + bytes.fromhex('0102030405060708'))

    def test_with_key_round_trip_is_twenty_octets(self) -> None:
        """An explicit ``rkey`` through ``TCP()`` packs a 20-octet option and reports it back."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.MP_CAPABLE,
                'skey': 0x0102030405060708,
                'rkey': 0x1112131415161718,
            })],
            **self.TCP_BASE,  # type: ignore[arg-type]
        )
        data = tcp.info.options[Enum_Option.Multipath_TCP]
        packed = bytes(tcp)

        self.assertEqual(data.length, 20)
        self.assertEqual(data.rkey, 0x1112131415161718)
        self.assertEqual(
            packed[-20:],
            bytes([0x1E, 0x14, 0x00, 0x00])
            + bytes.fromhex('0102030405060708')
            + bytes.fromhex('1112131415161718'),
        )


if __name__ == '__main__':
    unittest.main()
