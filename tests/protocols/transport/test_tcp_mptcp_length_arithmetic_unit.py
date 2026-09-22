# -*- coding: utf-8 -*-
"""Multipath TCP option lengths, re-derived from RFC 8684 at the six sites #576 names.

GitHub issue #576, the follow-up #567 invited ("worth checking the sibling ``_make_mptcp_*``
helpers' length arithmetic in the same pass") and #579 deliberately left alone, being scoped
to ``MPTCP.subtype`` and MP_CAPABLE.

An MPTCP option carries its own octet count in its ``Length`` field, and three separate
places have to agree on it: the ``_make_mptcp_*`` maker that *writes* that octet, the schema
in :mod:`pcapkit.protocols.schema.transport.tcp` whose fields actually *pack* the octets, and
the ``_read_mptcp_*`` reader whose guard *accepts* it coming back. Each of the six sites below
had at least one of the three disagreeing with :rfc:`8684`, and one had all three disagreeing
with each other.

What each site is, and where its number comes from
--------------------------------------------------

Every length here is derived from the figure named, by adding up the octets that figure
draws. The fixed head is 2 octets of ``Kind``/``Length`` plus the subtype row, which is 1
octet where the subtype's 4 bits are followed by 4 bits of flags or reserved, and 2 octets
where they are followed by 12 reserved bits.

* **MP_FASTCLOSE** -- :rfc:`8684` section 3.5, figure 14. Head 4 (``Kind`` 1 + ``Length`` 1 +
  subtype-and-12-reserved-bits 2) + the receiver's key 8 = **12**. The maker already wrote 12;
  :class:`~pcapkit.protocols.schema.transport.tcp.MPTCPFastclose` packed **11**, having no
  reserved field at all; and ``_read_mptcp_fastclose`` required **16**, a number neither of
  the other two nor the RFC produces. Note section 3.5, not 3.7: 3.7 is Fallback (MP_FAIL),
  and #576's own text -- and the ``EXPECTED_FAILURES`` entry it left behind -- cite 3.7 here
  in error.
* **MP_JOIN-SYN/ACK** -- :rfc:`8684` section 3.2, figure 6. Head 4 (``Kind`` 1 + ``Length`` 1 +
  subtype/rsv/``B`` 1 + ``Address ID`` 1) + the truncated HMAC 8 + the random number 4 =
  **16**. The maker wrote **12**, which is ``_make_join_syn``'s own correct length for the
  *SYN* form of figure 5 -- that one carries a 4-octet token where this one carries an
  8-octet HMAC -- copied across without recomputing. ``_read_join_synack`` independently
  required **20**, contradicting its own docstring figure.
* **MP_JOIN-ACK** -- :rfc:`8684` section 3.2, figure 7. Head 4 (``Kind`` 1 + ``Length`` 1 +
  subtype-and-12-reserved-bits 2) + the full 160-bit HMAC 20 = **24**. The maker wrote **8**.
  Its reader already required 24, so nothing the maker produced could be parsed back at all.
* **REMOVE_ADDR** -- :rfc:`8684` section 3.4.2, figure 13, which states ``Length = 3 + n``
  outright: head 3 (``Kind`` 1 + ``Length`` 1 + subtype-and-4-reserved-bits 1) + one octet per
  Address ID. The maker wrote a constant **4**, correct for exactly one list length -- and
  ``examples.generators.options``' fixture passes ``addr_id=[1]``, so the round-trip suite
  exercised only that one.
* **MP_PRIO** -- :rfc:`8684` section 3.3.8, figure 11: head 3 (``Kind`` 1 + ``Length`` 1 +
  subtype/rsv/``B`` 1) and **nothing else**, since section 5 of that document "specifies the
  removal of the AddrID field [RFC6824] in the MP_PRIO option", closing a theoretical attack
  in which a subflow could be forced into backup mode. So **3**, with :rfc:`6824`'s 4-octet
  Address ID form still accepted as legacy. The maker wrote a constant **4**, and because
  :attr:`~pcapkit.protocols.schema.transport.tcp.MPTCPPriority.addr_id` is conditional on
  ``pkt['length'] == 4``, that constant satisfied its own predicate: a caller who gave no
  Address ID got a phantom all-zero one anyway.
* **DSS** -- :rfc:`8684` section 3.3, figure 9. Head 4, then the Data ACK (4 octets, or 8 when
  ``a`` is set) if ``A``, the Data Sequence Number (4, or 8 when ``m`` is set), the Subflow
  Sequence Number (4), the Data-Level Length (2) and the Checksum (2) if ``M``. All flags set
  gives 28, which is the maximum the section states in prose.

DSS is the one entry that is not a defect where #576 puts it
------------------------------------------------------------

#576 files the DSS defect against ``_make_mptcp_dss``'s length expression and suggests the
fix "will also change what its maker needs to compute". Re-derived from figure 9, that
expression is **already correct**, and it is left untouched. Read as a base plus widening
increments rather than one term per field:

.. code-block:: python

    4 + (4 if flag_A else 0) + (4 if flag_a else 0) + (12 if flag_M else 0) + (4 if flag_m else 0)

the 4 is the head; ``A`` contributes the 4-octet Data ACK and ``a`` a further 4 to widen it to
8; ``M`` contributes 12 (a 4-octet DSN, the 4-octet SSN, the 2-octet Data-Level Length and the
2-octet Checksum) and ``m`` a further 4 to widen the DSN to 8. Every combination matches the
figure, and all flags set gives 4 + 4 + 4 + 12 + 4 = 28.

What was wrong was the *schema* that expression describes. ``MPTCPDSS.ack`` and ``MPTCPDSS.dsn``
sized themselves with ``NumberField(length=lambda pkt: 8 if pkt['flags']['a'] else 0)`` -- **0**
octets in the unextended case, where the figure says 4 -- so the option went onto the wire 4
(or, with both fields unextended, 8) octets shorter than its own ``Length`` octet declared, and
the ``ack``/``dsn`` values the caller supplied were simply not present. Measured pre-fix with
the generator's own override arguments: 12 octets packed against a declared 20.

A second defect sat behind the first: correcting the lambda to ``8 if ... else 4`` would still
not have packed *at the time*, because :class:`~pcapkit.corekit.fields.numbers.NumberField`
could not pack a callable length at all -- it called ``build_template`` once at ``__init__``
with the placeholder length ``-1``, latching ``_need_process = True``, and nothing cleared that
when ``__call__`` later resolved the real length and rebuilt the template as ``>I``/``>Q``.
Measured on the 8-octet form, which the old lambda did reach: ``_make_mptcp_dss(DSS, ack=1 <<
40)`` raised ``struct.error: required argument is not an integer``. #576 left that to
:mod:`pcapkit.corekit.fields.numbers`, and **#598 has since fixed it** by recomputing
``_need_process`` from the width in force rather than once from the placeholder, so a callable
length packs and unpacks both widths today. The schema keeps selecting between
:class:`~pcapkit.corekit.fields.numbers.UInt32Field` and
:class:`~pcapkit.corekit.fields.numbers.UInt64Field`, which each fix ``__template__`` at class
level, through a :class:`~pcapkit.corekit.fields.misc.SwitchField` -- the pattern
:func:`~pcapkit.protocols.schema.transport.tcp.mptcp_add_address_selector` already uses in that
module -- for the narrower reason recorded in
:func:`~pcapkit.protocols.schema.transport.tcp.mptcp_dss_ack_selector`'s own note, which is
about :class:`~pcapkit.corekit.fields.misc.ConditionalField`'s condition-blind ``length`` and
not about wire absence. Swapping the two would be a behaviour change and is not made here.
:class:`TCPMPTCPDSSExtendedFieldsUnitTests` covers the 8-octet forms that could not be packed
before at all.

MP_JOIN-SYN is not a defect either
-----------------------------------

#576's body lists three MP_JOIN forms and a comment on the issue corrects the attribution.
Re-derived here: :rfc:`8684` section 3.2 figure 5 gives ``Length = 12`` for the initial SYN --
head 4 (``Kind`` 1 + ``Length`` 1 + subtype/rsv/``B`` 1 + ``Address ID`` 1) + the receiver's
token 4 + the random number 4 -- ``_make_join_syn`` writes 12 and ``_read_join_syn`` guards
``!= 12``. All three agree. :class:`TCPMPTCPJoinSYNIsCorrectUnitTests` pins that, so a later
pass does not "fix" a correct number.

Coverage
--------

One test class per site, not one test for all six, so a regression names the option it broke.

Each class asserts the **byte-exact** packed option from its maker rather than only its
``length`` octet -- a declared length and a packed length can disagree, which is the whole
defect, so both are checked, and the octets themselves pin that the payload really is where
the figure puts it. Where the *reader* guard was also wrong (MP_FASTCLOSE, MP_JOIN-SYN/ACK) a
second test splices hand-built, spec-correct octets into a real TCP segment and parses them
back through :class:`~pcapkit.protocols.transport.tcp.TCP` proper, so a pack-side and a
parse-side bug cannot cancel out behind a closed round trip -- the pattern
:mod:`tests.protocols.transport.test_tcp_mptcp_capable_length_unit` established for #567, and
the blind spot :mod:`tests.protocols.test_option_roundtrip_unit`'s own docstring names ("a
defect can leave the cycle closed").

When this module was written MP_JOIN could not be built through the public ``TCP()``
constructor at all -- ``_make_mptcp_join`` dispatches on ``self._flags``, which ``TCP.make``
assigned *after* it had already built the options, so construction raised ``AttributeError:
'TCP' object has no attribute '_flags'``. That was a separate, already-recorded gap
(``tcp-mptcp/MP_JOIN`` in :data:`tests.protocols.test_option_roundtrip_unit.EXPECTED_FAILURES`,
with exactly that diagnosis) and was left alone here, which is why the MP_JOIN classes drive
the makers directly and reach the readers by parsing bytes, where ``_flags`` *is* set.

**#587 has since hoisted that assignment above the option build**, so the constructor route is
open now and its ``EXPECTED_FAILURES`` entry is gone;
:mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit` covers all three
layouts through ``TCP()`` proper. The classes here are still written against the makers, which
is what keeps them a check on the *length arithmetic* of each form rather than on the dispatch,
so they are left as they are -- but the reason is now choice rather than impossibility. C.f.
#587, #603.

"""
from __future__ import annotations

import unittest

#: Header fields shared by the constructed TCP segments here, matching
#: :data:`examples.generators.options.TCP_BASE` and
#: :data:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.TCP_BASE`.
TCP_BASE = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}

#: A spec-correct MP_FASTCLOSE, :rfc:`8684` section 3.5 figure 14: ``Kind`` ``0x1e``,
#: ``Length`` ``12``, the subtype nibble ``7`` (MP_FASTCLOSE) with its 12 reserved bits as
#: ``0x70 0x00``, then the receiver's key, 8 octets of ``0xCC``. Hand-built, not made.
MP_FASTCLOSE_SPEC_OCTETS = bytes([0x1E, 0x0C, 0x70, 0x00]) + b'\xCC' * 8

#: A spec-correct MP_JOIN-SYN/ACK, :rfc:`8684` section 3.2 figure 6: ``Kind`` ``0x1e``,
#: ``Length`` ``16``, the subtype nibble ``1`` (MP_JOIN) with ``B=0`` as ``0x10``, ``Address
#: ID`` ``0x05``, the truncated HMAC as 8 octets of ``0xDD``, then the random number
#: ``0x00000009``.
MP_JOIN_SYNACK_SPEC_OCTETS = (
    bytes([0x1E, 0x10, 0x10, 0x05]) + b'\xDD' * 8 + bytes([0x00, 0x00, 0x00, 0x09])
)


def build_tcp_segment(option_octets: 'bytes', *, syn: 'bool' = True,
                      ack_flag: 'bool' = False) -> 'bytes':
    """Pack a whole TCP segment carrying ``option_octets`` verbatim as its only option.

    Goes through :class:`~pcapkit.protocols.schema.transport.tcp.TCP` (the schema, not the
    protocol) directly, so nothing here calls a ``_make_mptcp_*`` maker: the option bytes
    reach the wire exactly as given.

    Args:
        option_octets: The whole option, header octets included, already padded to a multiple
            of 4 octets.
        syn: Whether to set the ``SYN`` flag.
        ack_flag: Whether to set the ``ACK`` flag.

    Returns:
        The packed TCP segment.

    Note:
        ``syn``/``ack_flag`` are parameters rather than fixed because the MP_JOIN *parse* path
        dispatches on them: ``TCP._read_mptcp_join`` picks between ``_read_join_syn``,
        ``_read_join_synack`` and ``_read_join_ack`` by inspecting ``self._flags``, which the
        read path sets from these very bits. A SYN/ACK option in a SYN-only segment would be
        routed to the wrong reader.

        ``Schema_TCP`` is imported inside the function, not at module level -- see
        :func:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.build_mptcp_option`'s own
        docstring for why: a name bound to ``pcapkit`` at collection time can go stale once
        another module in this suite pops ``pcapkit``'s submodules out of ``sys.modules``.

    """
    from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP

    if len(option_octets) % 4:
        raise ValueError('option_octets must already be a multiple of 4 octets long')

    schema = Schema_TCP(
        srcport=50000, dstport=80, seq=1, ack=0,
        offset={'offset': 5 + len(option_octets) // 4, 'ns': 0},
        flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': int(ack_flag), 'psh': 0, 'rst': 0,
               'syn': int(syn), 'fin': 0},
        window=8192, checksum=b'\x00\x00', urgent=0,
        options=option_octets,
        payload=b'',
    )
    return schema.pack()


def make(meth: 'str', subtype_name: 'str', **kwargs: 'object') -> 'bytes':
    """Build an MPTCP option through one maker and pack it.

    Args:
        meth: Name of the ``_make_*`` method under test.
        subtype_name: Attribute name on
            :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption` for the subtype to pass.
        **kwargs: forwarded to the maker as the option's own arguments.

    Returns:
        The packed option bytes.

    """
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    from pcapkit.protocols.transport.tcp import TCP

    tcp = TCP.__new__(TCP)
    schema = getattr(tcp, meth)(getattr(Enum_MPTCPOption, subtype_name), **kwargs)
    return schema.pack()


class LengthInvariantMixin:
    """The one invariant every site below broke: declared length is packed length."""

    def assertLengthMatchesWire(self, packed: 'bytes', expected: 'int') -> 'None':  # noqa: N802
        """Assert ``packed`` is ``expected`` octets long and says so in its length octet.

        Args:
            packed: The packed option.
            expected: The octet count :rfc:`8684` gives for this form.

        """
        self.assertEqual(len(packed), expected,  # type: ignore[attr-defined]
                         'the option must occupy the octet count RFC 8684 gives')
        self.assertEqual(packed[1], expected,  # type: ignore[attr-defined]
                         'the declared length octet must match the wire length')


class TCPMPTCPFastcloseLengthUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 1 -- MP_FASTCLOSE is 12 octets: :rfc:`8684` section 3.5, figure 14."""

    def test_maker_packs_twelve_octets(self) -> None:
        """``_make_mptcp_fastclose`` packs 12 octets, reserved octet included.

        Pre-fix this packed **11** -- ``1e0c700000000000000009``, a declared 12 against an
        11-octet option -- because ``MPTCPFastclose`` had no reserved field and ``test`` was
        the only octet between ``length`` and ``key``, where figure 14 draws 4 subtype bits
        followed by 12 reserved ones.

        """
        packed = make('_make_mptcp_fastclose', 'MP_FASTCLOSE', key=9)

        self.assertLengthMatchesWire(packed, 12)
        self.assertEqual(packed, bytes([0x1E, 0x0C, 0x70, 0x00]) + (9).to_bytes(8, 'big'))

    def test_spec_octets_parse_back(self) -> None:
        """Hand-built figure 14 octets parse, with the key intact.

        Pre-fix ``_read_mptcp_fastclose`` required ``schema.length == 16``, so a
        spec-correct 12-octet option off the wire raised ``ProtocolError: TCP: [OptNo 30]
        invalid format`` -- and so did every option the maker produced, since it declared
        the correct 12.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(MP_FASTCLOSE_SPEC_OCTETS)
        data = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_FASTCLOSE)
        self.assertEqual(data.length, 12)
        self.assertEqual(data.rkey, 0xCCCCCCCCCCCCCCCC)

    def test_public_constructor_round_trips(self) -> None:
        """MP_FASTCLOSE builds through ``TCP()`` and reports itself back.

        This is the case ``tcp-mptcp/MP_FASTCLOSE`` records in
        :data:`tests.protocols.test_option_roundtrip_unit.EXPECTED_FAILURES`: the maker's
        *correct* length failing the parser's wrong check made the whole construction raise.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.MP_FASTCLOSE,
                'key': 0x0102030405060708,
            })],
            **TCP_BASE,  # type: ignore[arg-type]
        )
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.length, 12)
        self.assertEqual(data.rkey, 0x0102030405060708)
        self.assertEqual(
            bytes(tcp)[-12:],
            bytes([0x1E, 0x0C, 0x70, 0x00]) + bytes.fromhex('0102030405060708'),
        )


class TCPMPTCPJoinSYNACKLengthUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 2 -- MP_JOIN-SYN/ACK is 16 octets: :rfc:`8684` section 3.2, figure 6."""

    def test_maker_packs_sixteen_octets(self) -> None:
        """``_make_join_synack`` packs 16 octets and declares 16.

        Pre-fix it declared **12** -- ``_make_join_syn``'s length for figure 5's SYN form --
        while packing the 16 octets figure 6 requires, since the HMAC here is 8 octets where
        the SYN's token is 4.

        """
        packed = make('_make_join_synack', 'MP_JOIN', addr_id=5, hmac=b'\xDD' * 8, nonce=9)

        self.assertLengthMatchesWire(packed, 16)
        self.assertEqual(
            packed,
            bytes([0x1E, 0x10, 0x10, 0x05]) + b'\xDD' * 8 + bytes([0x00, 0x00, 0x00, 0x09]),
        )

    def test_spec_octets_parse_back(self) -> None:
        """Hand-built figure 6 octets parse in a SYN/ACK segment.

        Pre-fix ``_read_join_synack`` required ``schema.length == 20`` -- a value neither
        figure 6 nor ``MPTCPJoinSYNACK`` produces, and one that contradicted this method's
        own docstring figure -- so a spec-correct 16-octet option was rejected as an invalid
        format.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(MP_JOIN_SYNACK_SPEC_OCTETS, syn=True, ack_flag=True)
        data = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
        self.assertEqual(data.length, 16)
        self.assertEqual(data.addr_id, 5)
        self.assertEqual(data.hmac, b'\xDD' * 8)
        self.assertEqual(data.nonce, 9)

    def test_reconstruction_keeps_the_parsed_hmac(self) -> None:
        """Rebuilding from parsed data preserves ``hmac``, which used to be dropped.

        ``_make_join_synack``'s ``if opt is not None:`` branch set ``backup``, ``addr_id``
        and ``nonce`` -- the last of those twice, on two consecutive lines -- but never
        ``hmac``, so reconstructing a parsed MP_JOIN-SYN/ACK silently substituted the
        ``bytes(8)`` default for the truncated HMAC that was actually on the wire. The HMAC
        is the entire authentication payload of this form of the option, so an all-zero
        substitute is not a cosmetic loss.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(MP_JOIN_SYNACK_SPEC_OCTETS, syn=True, ack_flag=True)
        parsed = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

        rebuilt = TCP.__new__(TCP)._make_join_synack(Enum_MPTCPOption.MP_JOIN, parsed).pack()  # pylint: disable=protected-access

        self.assertNotEqual(rebuilt[4:12], bytes(8), 'the HMAC must not come back all-zero')
        self.assertEqual(rebuilt[4:12], b'\xDD' * 8)
        self.assertEqual(rebuilt, MP_JOIN_SYNACK_SPEC_OCTETS)
        self.assertEqual(Enum_Option.Multipath_TCP, rebuilt[0])


class TCPMPTCPJoinACKLengthUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 3 -- MP_JOIN-ACK is 24 octets: :rfc:`8684` section 3.2, figure 7."""

    def test_maker_packs_twenty_four_octets(self) -> None:
        """``_make_join_ack`` packs 24 octets and declares 24.

        Pre-fix it declared **8**, a third of the truth, while packing the 24 octets figure 7
        requires: the 160-bit HMAC alone is 20. ``_read_join_ack`` already required 24, so
        nothing this maker produced could be parsed back.

        """
        packed = make('_make_join_ack', 'MP_JOIN', hmac=b'\xBB' * 20)

        self.assertLengthMatchesWire(packed, 24)
        self.assertEqual(packed, bytes([0x1E, 0x18, 0x10, 0x00]) + b'\xBB' * 20)

    def test_maker_output_satisfies_its_own_reader(self) -> None:
        """What the maker declares is what the reader accepts.

        The two disagreed absolutely before the fix -- 8 against a guard of 24 -- so this is
        the pairing that could not hold at all, rather than an off-by-one.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP.__new__(TCP)
        schema = tcp._make_join_ack(Enum_MPTCPOption.MP_JOIN, hmac=b'\xBB' * 20)  # pylint: disable=protected-access
        object.__setattr__(schema, 'subtype', Enum_MPTCPOption.MP_JOIN)

        data = tcp._read_join_ack(schema, options=OrderedMultiDict())  # pylint: disable=protected-access

        self.assertEqual(data.length, 24)
        self.assertEqual(data.hmac, b'\xBB' * 20)


class TCPMPTCPRemoveAddressLengthUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 4 -- REMOVE_ADDR is ``3 + n``: :rfc:`8684` section 3.4.2, figure 13."""

    def test_two_address_ids_pack_five_octets(self) -> None:
        """``addr_id=[1, 2]`` packs 5 octets and declares 5.

        Stated as its own test, not only as a case of the ``subTest`` sweep below, because
        pytest 9.1.1 here has no ``pytest-subtests``: a failing ``subTest`` is reported but
        its *parent* test still prints ``PASSED``, so a per-site regression is easier to read
        from a test that fails outright. Pre-fix this packed ``1e04400102`` -- 5 octets
        declaring 4.

        """
        packed = make('_make_mptcp_remove', 'REMOVE_ADDR', addr_id=[1, 2])

        self.assertLengthMatchesWire(packed, 5)
        self.assertEqual(packed, bytes([0x1E, 0x05, 0x40, 0x01, 0x02]))

    def test_length_tracks_the_number_of_address_ids(self) -> None:
        """``3 + n`` for every ``n``, not a constant 4.

        Pre-fix, measured: ``addr_id=[1, 2]`` packed 5 octets declaring 4, ``addr_id=[]``
        packed 3 declaring 4, and ``addr_id=[1, 2, 3, 4]`` packed 7 declaring 4. Only
        ``addr_id=[1]`` -- which is what ``examples.generators.options``' fixture passes --
        happened to agree, which is why the round-trip suite never saw this.

        """
        for addr_ids in ([], [1], [1, 2], [1, 2, 3, 4], list(range(1, 21))):
            with self.subTest(addr_ids=addr_ids):
                packed = make('_make_mptcp_remove', 'REMOVE_ADDR', addr_id=addr_ids)

                self.assertLengthMatchesWire(packed, 3 + len(addr_ids))
                self.assertEqual(packed, bytes([0x1E, 3 + len(addr_ids), 0x40])
                                 + bytes(addr_ids))

    def test_public_constructor_reports_every_address_id(self) -> None:
        """A multi-ID REMOVE_ADDR round-trips through ``TCP()`` with all IDs intact.

        The declared length is what
        :attr:`~pcapkit.protocols.schema.transport.tcp.MPTCPRemoveAddress.addr_id` sizes its
        list from, as ``pkt['length'] - 3``, so the old constant 4 truncated the parse to a
        single ID as well as mis-declaring the pack.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.REMOVE_ADDR,
                'addr_id': [7, 8, 9],
            })],
            **TCP_BASE,  # type: ignore[arg-type]
        )
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.length, 6)
        self.assertEqual(data.addr_id, (7, 8, 9))


class TCPMPTCPPriorityLengthUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 5 -- MP_PRIO is 3 octets: :rfc:`8684` section 3.3.8, figure 11."""

    def test_no_address_id_packs_three_octets(self) -> None:
        """``addr_id=None`` packs 3 octets with no Address ID at all.

        Pre-fix this packed ``1e045000`` -- 4 octets, the last a phantom all-zero Address ID
        no caller asked for. The constant ``length=4`` satisfied ``MPTCPPriority.addr_id``'s
        own ``pkt['length'] == 4`` predicate, so declaring the legacy length *created* the
        legacy field.

        """
        packed = make('_make_mptcp_prio', 'MP_PRIO')

        self.assertLengthMatchesWire(packed, 3)
        self.assertEqual(packed, bytes([0x1E, 0x03, 0x50]))

    def test_backup_flag_is_packed_without_an_address_id(self) -> None:
        """``B`` still reaches the wire in the 3-octet form."""
        packed = make('_make_mptcp_prio', 'MP_PRIO', backup=True)

        self.assertLengthMatchesWire(packed, 3)
        self.assertEqual(packed, bytes([0x1E, 0x03, 0x51]))

    def test_explicit_address_id_keeps_the_legacy_four_octet_form(self) -> None:
        """An explicit ``addr_id`` still packs :rfc:`6824`'s 4-octet form.

        :rfc:`8684` removed the field, but the schema and ``_read_mptcp_prio`` both still
        accept it, so the length has to follow whether one was actually given rather than
        collapsing to 3 unconditionally.

        """
        packed = make('_make_mptcp_prio', 'MP_PRIO', addr_id=7)

        self.assertLengthMatchesWire(packed, 4)
        self.assertEqual(packed, bytes([0x1E, 0x04, 0x50, 0x07]))

    def test_reconstruction_keeps_the_parsed_backup_flag(self) -> None:
        """Rebuilding from parsed data preserves ``backup``, which used to be dropped.

        ``_make_mptcp_prio``'s ``if opt is not None:`` branch set only ``addr_id``, so a
        parsed MP_PRIO with ``B=1`` was rebuilt with ``B=0`` -- and ``B`` is the entire
        payload of this option, so the rebuilt option said the opposite of the original.
        The same shape as ``_make_join_synack``'s dropped ``hmac``.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(bytes([0x1E, 0x03, 0x51, 0x00]))
        parsed = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]
        self.assertTrue(parsed.backup, 'the hand-built option must carry B=1 to begin with')

        rebuilt = TCP.__new__(TCP)._make_mptcp_prio(Enum_MPTCPOption.MP_PRIO, parsed).pack()  # pylint: disable=protected-access

        self.assertEqual(rebuilt, bytes([0x1E, 0x03, 0x51]))
        self.assertEqual(Enum_Option.Multipath_TCP, rebuilt[0])


class TCPMPTCPDSSLengthUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 6 -- DSS packs what it declares: :rfc:`8684` section 3.3, figure 9."""

    def test_data_ack_only_packs_eight_octets(self) -> None:
        """``A`` set, ``a`` clear: head 4 + a 4-octet Data ACK = 8.

        Pre-fix this packed ``1e082001`` -- 4 octets declaring 8 -- because ``MPTCPDSS.ack``
        sized itself ``8 if pkt['flags']['a'] else 0`` and so contributed nothing at all.
        The ``ack`` value the caller passed was not on the wire.

        """
        packed = make('_make_mptcp_dss', 'DSS', ack=1)

        self.assertLengthMatchesWire(packed, 8)
        self.assertEqual(packed, bytes([0x1E, 0x08, 0x20, 0x01]) + (1).to_bytes(4, 'big'))

    def test_mapping_only_packs_sixteen_octets(self) -> None:
        """``M`` set, ``m`` clear: head 4 + DSN 4 + SSN 4 + Data-Level Length 2 + Checksum 2.

        Pre-fix ``MPTCPDSS.dsn`` contributed 0 octets here for the same reason as ``ack``, so
        this packed 12 against a declared 16 and the ``dsn`` value was lost.

        """
        packed = make('_make_mptcp_dss', 'DSS', dsn=2, ssn=3, dl_len=4, checksum=b'\x00\x00')

        self.assertLengthMatchesWire(packed, 16)
        self.assertEqual(
            packed,
            bytes([0x1E, 0x10, 0x20, 0x04]) + (2).to_bytes(4, 'big') + (3).to_bytes(4, 'big')
            + (4).to_bytes(2, 'big') + b'\x00\x00',
        )

    def test_generator_override_arguments_pack_twenty_octets(self) -> None:
        """The exact arguments ``examples.generators.options`` uses pack their declared 20.

        This is #576's filed measurement: ``ack=1, dsn=2, ssn=3, dl_len=4,
        checksum=b'\\x00\\x00'`` packed **12** octets against a declared 20, with neither
        ``ack`` nor ``dsn`` on the wire. ``tcp-mptcp/DSS`` still read ``'OK'`` in the
        round-trip suite, because construct -> parse -> reconstruct produced the same wrong
        12 octets every time and the suite only checks the cycle is self-consistent.

        """
        packed = make('_make_mptcp_dss', 'DSS', ack=1, dsn=2, ssn=3, dl_len=4,
                      checksum=b'\x00\x00')

        self.assertLengthMatchesWire(packed, 20)
        self.assertEqual(
            packed,
            bytes([0x1E, 0x14, 0x20, 0x05]) + (1).to_bytes(4, 'big') + (2).to_bytes(4, 'big')
            + (3).to_bytes(4, 'big') + (4).to_bytes(2, 'big') + b'\x00\x00',
        )

    def test_ack_and_dsn_survive_a_real_byte_round_trip(self) -> None:
        """A DSS built through ``TCP()``, packed, and re-parsed still carries ``ack``/``dsn``.

        The re-parse is the point, and asserting on the *constructed* ``tcp.info`` instead
        would prove nothing: ``TCP._make_mode_mp`` hands the schema it just built straight to
        the matching ``_read_mptcp_*``, so ``data.ack`` reads back the attribute the caller
        set regardless of how many octets the field packed. Measured -- that assertion passes
        against the unfixed tree. Going out to bytes and back in is what exposes a field that
        declared 4 octets and packed 0.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.DSS,
                'ack': 0x11223344, 'dsn': 0x55667788, 'ssn': 3, 'dl_len': 4,
                'checksum': b'\x00\x00',
            })],
            **TCP_BASE,  # type: ignore[arg-type]
        )
        raw = bytes(tcp)
        reparsed = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(reparsed.length, 20)
        self.assertEqual(reparsed.ack, 0x11223344)
        self.assertEqual(reparsed.dsn, 0x55667788)
        self.assertEqual(reparsed.ssn, 3)
        self.assertEqual(reparsed.dl_len, 4)


class TCPMPTCPDSSExtendedFieldsUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Site 6, second half -- the 8-octet DSS forms, which could not be packed at all.

    ``MPTCPDSS.ack``/``.dsn`` used ``NumberField(length=<callable>)``, and that field latches
    ``_need_process = True`` at ``__init__`` from the placeholder length ``-1`` and never
    clears it, so once ``__call__`` resolved a real width of 8 and rebuilt the template as
    ``>Q``, ``pre_process`` handed :func:`struct.pack` bytes for an integer template. Every
    test in this class raised ``struct.error: required argument is not an integer`` before the
    fix -- not a wrong length, no length at all.

    """

    def test_extended_data_ack_packs_eight_octets(self) -> None:
        """``a`` set: the Data ACK widens to 8 octets, head 4 + 8 = 12."""
        packed = make('_make_mptcp_dss', 'DSS', ack=1 << 40)

        self.assertLengthMatchesWire(packed, 12)
        self.assertEqual(packed,
                         bytes([0x1E, 0x0C, 0x20, 0x03]) + (1 << 40).to_bytes(8, 'big'))

    def test_extended_dsn_packs_eight_octets(self) -> None:
        """``m`` set: the DSN widens to 8 octets, head 4 + 8 + SSN 4 + 2 + 2 = 20.

        The flags octet is ``0x0c``: figure 9 orders the low bits ``F|m|M|a|A``, so with only
        ``M`` and ``m`` set the octet is ``m << 3 | M << 2``.

        """
        packed = make('_make_mptcp_dss', 'DSS', dsn=2 << 40, ssn=3, dl_len=4,
                      checksum=b'\x00\x00')

        self.assertLengthMatchesWire(packed, 20)
        self.assertEqual(
            packed,
            bytes([0x1E, 0x14, 0x20, 0x0C]) + (2 << 40).to_bytes(8, 'big')
            + (3).to_bytes(4, 'big') + (4).to_bytes(2, 'big') + b'\x00\x00',
        )

    def test_all_flags_set_packs_the_rfc_maximum_of_twenty_eight(self) -> None:
        """Every flag set gives 28 octets, the maximum section 3.3 states in prose.

        The prose figure is the independent check on the arithmetic: "the maximum length of
        this option, with all flags set, is 28 octets" is stated in words, not derived from
        the diagram, so matching it confirms the per-field widths add up as figure 9 draws
        them.

        """
        packed = make('_make_mptcp_dss', 'DSS', data_fin=True, ack=1 << 40, dsn=2 << 40,
                      ssn=3, dl_len=4, checksum=b'\x00\x00')

        self.assertLengthMatchesWire(packed, 28)
        self.assertEqual(
            packed,
            bytes([0x1E, 0x1C, 0x20, 0x1F]) + (1 << 40).to_bytes(8, 'big')
            + (2 << 40).to_bytes(8, 'big') + (3).to_bytes(4, 'big') + (4).to_bytes(2, 'big')
            + b'\x00\x00',
        )


class TCPMPTCPJoinSYNIsCorrectUnitTests(LengthInvariantMixin, unittest.TestCase):
    """Not a defect -- MP_JOIN-SYN is 12 octets: :rfc:`8684` section 3.2, figure 5.

    #576's body groups the three MP_JOIN forms together and a comment on the issue corrects
    the attribution to the SYN/ACK and ACK forms only. Pinned here so a later pass reading
    the body alone does not "correct" a number that is already right: head 4 (``Kind`` 1 +
    ``Length`` 1 + subtype/rsv/``B`` 1 + ``Address ID`` 1) + the receiver's token 4 + the
    sender's random number 4 = 12, which is what figure 5 labels ``Length = 12``, what
    ``_make_join_syn`` writes, and what ``_read_join_syn`` guards on.

    """

    def test_maker_packs_twelve_octets(self) -> None:
        """``_make_join_syn`` packs 12 octets and declares 12, before and after #576."""
        packed = make('_make_join_syn', 'MP_JOIN', addr_id=1, token=2, nonce=3)

        self.assertLengthMatchesWire(packed, 12)
        self.assertEqual(
            packed,
            bytes([0x1E, 0x0C, 0x10, 0x01]) + (2).to_bytes(4, 'big') + (3).to_bytes(4, 'big'),
        )

    def test_spec_octets_parse_back_in_a_syn_segment(self) -> None:
        """Hand-built figure 5 octets parse, confirming the reader guard is right too."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(bytes([0x1E, 0x0C, 0x11, 0x02])
                                + (3).to_bytes(4, 'big') + (4).to_bytes(4, 'big'))
        data = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
        self.assertEqual(data.length, 12)
        self.assertTrue(data.backup)
        self.assertEqual(data.addr_id, 2)
        self.assertEqual(data.token, 3)
        self.assertEqual(data.nonce, 4)


if __name__ == '__main__':
    unittest.main()
