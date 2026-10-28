# -*- coding: utf-8 -*-
"""``TCP.make`` resolves the connection flags before it builds the options.

GitHub issue #587. Distinct from #576/#585, which are about MPTCP option *length*
arithmetic; this one is a statement-ordering defect in
:meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>`.

The ordering
------------

:meth:`TCP._make_mptcp_join <pcapkit.protocols.transport.tcp.TCP._make_mptcp_join>`,
reached from ``_make_tcp_options``, *branches on* ``self._flags`` to pick which of the
three MP_JOIN layouts to emit, so :meth:`~pcapkit.protocols.transport.tcp.TCP.make` has
to assign the flags before it builds the options. Built the other way round:

.. code-block:: python

    options_value, total_length = self._make_tcp_options(options)
    ...
    self._flags = _flag

a fresh instance has no such attribute yet, and construction dies outright::

    AttributeError: 'TCP' object has no attribute '_flags'

The parse path has the identical pair of branches in ``_read_mptcp_join``, and
:meth:`~pcapkit.protocols.transport.tcp.TCP.read` assigns ``self._flags`` before it
parses the options. In ``make`` the ``flags`` dict and the ``_flag`` accumulation sit
above the ``_make_tcp_options`` call; the ``offset`` computation stays below it, being the
one statement in that block that genuinely depends on the options' ``total_length``.

Why the branch is not the thing to remove
------------------------------------------

MP_JOIN really is flag-dependent. :rfc:`8684` section 3.2 gives it three distinct
layouts, and they are three different lengths, so a single form cannot serve:

============== ========= ======== ==================================================
Segment        Figure     Length   Payload after the 2-octet ``Kind``/``Length``
============== ========= ======== ==================================================
SYN            figure 5      12   subtype/rsv/``B`` 1, ``Address ID`` 1, token 4,
                                  random number 4
SYN/ACK        figure 6      16   subtype/rsv/``B`` 1, ``Address ID`` 1, truncated
                                  HMAC 8, random number 4
ACK            figure 7      24   subtype and 12 reserved bits 2, full HMAC 20
============== ========= ======== ==================================================

Those octet counts are the makers' own (#585), and they are re-asserted here from the
same figures, because a layout chosen correctly and then sized wrongly is no better than
the crash.

Why a zero initialisation is not enough
----------------------------------------

The obvious alternative -- give ``_flags`` a class-level default of zero so the attribute
always exists -- is worse than the crash, and
:class:`TCPMPTCPJoinStaleFlagsUnitTests` is the case that shows why.

:meth:`Protocol.pack <pcapkit.protocols.protocol.Protocol.pack>` is public and calls
``make``, so an instance that has already *parsed* a segment can be asked to build a
different one. That instance's ``_flags`` is already set -- to the parsed segment's flags
-- so a zero default never comes into play for it, and with the options built first it
silently builds the option for the wrong segment. Measured that way on a parsed
MP_JOIN-SYN instance asked to pack an MP_JOIN-ACK segment::

    c3500050 00000001 00000000 8010 2000 0000 0000  1e0c 10 00 00000000 00000000

The header's flag octet is ``0x10``, ACK, as requested; the option is ``1e0c…``, the
**12-octet SYN form** of figure 5, and the caller's 20-octet HMAC -- the entire
authentication payload of figure 7's form, and the only reason to send it -- is gone,
replaced by an all-zero phantom token and nonce. Nothing raises. A receiver gets a
self-inconsistent segment.

Built in the right order, the same call emits ``1e18 10 00`` followed by the 20 HMAC
octets: figure 7, length 24.

So the crash is the *benign* symptom and the ordering is the defect. Resolving the flags
first prevents both outcomes; a zero default prevents only the fresh-instance crash, and
converts the flagless case from a crash into a spurious error while leaving the silent
corruption exactly as it is.

The flagless seed
------------------

An MP_JOIN asked for on a segment with neither SYN nor ACK set ends in
``_make_mptcp_join``'s :exc:`~pcapkit.utilities.exceptions.ProtocolError`. Reaching it
needs a real flagless seed for the accumulator: seeded with ``cast('Enum_Flags', 0)`` --
and :func:`typing.cast` is a runtime no-op -- ``self._flags`` would stay the plain
:class:`int` ``0`` with no flag set, and the first membership test would raise instead::

    TypeError: argument of type 'int' is not a container or iterable

Seeding with ``Enum_Flags(0)`` -- a real, flagless :class:`aenum.IntFlag` member, which
compares equal to ``0`` and ORs the same way -- lets the library's own documented error
surface. :class:`TCPMPTCPJoinFlagOrderingUnitTests` pins that it is a ``ProtocolError``,
since a bare :exc:`TypeError` escaping the library would break the in-library exception
contract.

On the read path,
:func:`~pcapkit.protocols.schema.transport.tcp.mptcp_data_selector` guards the flagless
case and raises :exc:`~pcapkit.utilities.exceptions.FieldError` before
``_read_mptcp_join`` is reached at all, and ``read`` seeds ``Enum_Flags(0)`` as well
(#616).

Relationship to the rest of the suite
--------------------------------------

Everything here goes through the **public** constructor, ``TCP(options=[(code, kwargs)],
…)``, or through ``pack`` on an instance that has parsed. That matters: the MP_JOIN cases
in :mod:`tests.protocols.transport.test_tcp_mptcp_length_arithmetic_unit` call
``_make_join_syn``/``_make_join_synack``/``_make_join_ack`` directly on a
``TCP.__new__(TCP)``, which is precisely how they sidestep ``_make_mptcp_join`` and its
``self._flags`` read -- so none of them can catch an inverted order. The public path is
the one #587 is about.

"""
from __future__ import annotations

import inspect
import unittest

#: Header fields shared by every constructed segment here, spelled with the parameter
#: names :meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>` actually declares.
#:
#: Deliberately *not* a copy of :data:`examples.generators.options.TCP_BASE`, which
#: sibling modules in this directory mirror -- and, unlike theirs, this dict omits
#: ``syn``/``ack`` altogether, since every case here passes those two explicitly to
#: select a layout, where a shared constant could not. The names matter: ``ack`` is the
#: *acknowledgement flag*, not ``ack_no``, and ``make`` raises ``UnsupportedCall`` for any
#: keyword it does not declare (#617), so a ``seq`` or an ``ack_flag`` would be refused
#: rather than silently swallowed by its ``**kwargs``. This module dispatches on the ACK
#: flag, so it cannot leave which-``ack``-is-which to inference.
TCP_HEADER = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False,
    'psh': False, 'rst': False, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}

#: Figure 5 of :rfc:`8684` section 3.2, as octets: ``Kind`` 30, ``Length`` 12, subtype 1
#: (MP_JOIN) in the high nibble with ``B`` clear, ``Address ID`` 1, then the 32-bit
#: receiver's token and the 32-bit sender's random number.
MP_JOIN_SYN_OCTETS = bytes([0x1E, 0x0C, 0x10, 0x01]) + b'\xAA' * 4 + b'\xBB' * 4

#: Figure 6 of :rfc:`8684` section 3.2: ``Length`` 16, ``Address ID`` 2, an 8-octet
#: truncated HMAC, then the 32-bit random number.
MP_JOIN_SYNACK_OCTETS = bytes([0x1E, 0x10, 0x10, 0x02]) + b'\xCC' * 8 + b'\xDD' * 4

#: Figure 7 of :rfc:`8684` section 3.2: ``Length`` 24, two octets of subtype and 12
#: reserved bits, then the full 160-bit HMAC.
MP_JOIN_ACK_OCTETS = bytes([0x1E, 0x18, 0x10, 0x00]) + b'\xEE' * 20


def build_join(*, syn: 'bool', ack: 'bool', **option: 'object') -> 'object':
    """Build a whole TCP segment carrying one MP_JOIN option, through the public API.

    Args:
        syn: Whether to set the ``SYN`` flag, which selects the option layout.
        ack: Whether to set the ``ACK`` flag, which selects the option layout.
        **option: forwarded to the matching ``_make_join_*`` maker as the option's own
            arguments.

    Returns:
        The constructed :class:`~pcapkit.protocols.transport.tcp.TCP` instance.

    Note:
        :mod:`pcapkit` is imported inside the function rather than at module level, for
        the reason
        :func:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.build_mptcp_option`
        documents at length: other modules in this suite purge ``pcapkit``'s submodules
        from :data:`sys.modules`, so a name bound at collection time can end up pointing
        at a schema class built from a stale ``Schema`` base.

    """
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    from pcapkit.const.tcp.option import Option as Enum_Option
    from pcapkit.protocols.transport.tcp import TCP

    args = dict(option)
    args['subtype'] = Enum_MPTCPOption.MP_JOIN
    return TCP(syn=syn, ack=ack,
               options=[(Enum_Option.Multipath_TCP, args)],  # type: ignore[arg-type]
               **TCP_HEADER)


def build_tcp_segment(option_octets: 'bytes', *, syn: 'bool', ack: 'bool') -> 'bytes':
    """Pack a segment carrying ``option_octets`` verbatim, bypassing every maker.

    Goes through the *schema* rather than the protocol, so the option bytes reach the
    wire exactly as given and the parse path can be exercised against hand-derived
    figures. The same helper, and the same reason for it, as
    :func:`tests.protocols.transport.test_tcp_mptcp_length_arithmetic_unit.build_tcp_segment`.

    Args:
        option_octets: The whole option, already a multiple of 4 octets long.
        syn: Whether to set the ``SYN`` flag.
        ack: Whether to set the ``ACK`` flag.

    Returns:
        The packed TCP segment.

    Raises:
        ValueError: If ``option_octets`` is not a multiple of 4 octets long, which would
            make the header's ``offset`` unrepresentable.

    """
    from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP

    if len(option_octets) % 4:
        raise ValueError('option_octets must already be a multiple of 4 octets long')

    schema = Schema_TCP(
        srcport=50000, dstport=80, seq=1, ack=0,
        offset={'offset': 5 + len(option_octets) // 4, 'reserved': 0, 'ns': 0},
        flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': int(ack), 'psh': 0, 'rst': 0,
               'syn': int(syn), 'fin': 0},
        window=8192, checksum=b'\x00\x00', urgent=0,
        options=option_octets,
        payload=b'',
    )
    return schema.pack()


class JoinLayoutMixin:
    """The invariant every case below shares: the layout matches the figure named."""

    def assertJoinLayout(self, tcp: 'object', expected: 'bytes') -> 'None':  # noqa: N802
        """Assert ``tcp`` carries exactly ``expected`` as its options, and says so.

        Three separate claims, because a layout can be picked correctly and still be
        wrong: the option octets are what the figure draws, the option's own ``Length``
        octet agrees with how many octets it actually occupies, and the header's
        ``offset`` accounts for them -- the last being what proves the ``offset``
        computation sees the options it is supposed to count, with the flag resolution
        placed ahead of the option build.

        Args:
            tcp: The constructed :class:`~pcapkit.protocols.transport.tcp.TCP` instance.
            expected: The option octets :rfc:`8684` gives for this form.

        """
        octets = bytes(tcp)  # type: ignore[call-overload]

        self.assertEqual(octets[20:], expected,  # type: ignore[attr-defined]
                         'the option must be the octets RFC 8684 section 3.2 draws')
        self.assertEqual(octets[21], len(expected),  # type: ignore[attr-defined]
                         'the declared length octet must match the wire length')
        self.assertEqual((octets[12] >> 4) * 4, 20 + len(expected),  # type: ignore[attr-defined]
                         'the header offset must still count the options')


class TCPMPTCPJoinFlagOrderingUnitTests(JoinLayoutMixin, unittest.TestCase):
    """Each of the three MP_JOIN layouts builds through the public constructor.

    With the options built before the flags, every one of these raises ``AttributeError:
    'TCP' object has no attribute '_flags'`` before returning anything, leaving no instance
    to assert on at all.

    """

    def test_the_issue_reproduction_constructs(self) -> None:
        """#587's reproduction returns an instance instead of raising.

        The issue's own call, with ``seq`` spelled ``seq_no``: ``make`` (like ``read``,
        ``pack``, ``unpack``, ``__post_init__`` and ``__init__``) declares no ``seq``
        parameter, and an undeclared keyword raises
        :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` (#617), for a reason that has
        nothing to do with what this test is pinning. ``ack=0`` is kept as filed: ``ack``
        *is* a real parameter -- the connection flag, not the acknowledgement number --
        and ``0`` is an accepted falsy value for it. The case returns an instance rather
        than raising ``AttributeError: 'TCP' object has no attribute '_flags'``, which is
        what #587 is about.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(srcport=1, dstport=2, seq_no=0, ack=0, syn=True,
                  options=[(Enum_Option.Multipath_TCP,
                            {'subtype': Enum_MPTCPOption.MP_JOIN, 'backup': False,
                             'addr_id': 1, 'token': 7, 'nonce': 9})])

        data = tcp.info.options[Enum_Option.Multipath_TCP]
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
        self.assertEqual(data.token, 7)
        self.assertEqual(data.nonce, 9)

    def test_syn_builds_figure_5(self) -> None:
        """SYN alone selects the 12-octet MP_JOIN-SYN form: section 3.2, figure 5."""
        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_join(syn=True, ack=False, backup=False, addr_id=1,
                         token=0xAAAAAAAA, nonce=0xBBBBBBBB)
        data = tcp.info.options[Enum_Option.Multipath_TCP]  # type: ignore[attr-defined]

        self.assertJoinLayout(tcp, MP_JOIN_SYN_OCTETS)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
        self.assertEqual(data.length, 12)
        self.assertEqual(data.connection, Enum_Flags.SYN)
        self.assertEqual(data.addr_id, 1)
        self.assertEqual(data.token, 0xAAAAAAAA)
        self.assertEqual(data.nonce, 0xBBBBBBBB)

    def test_syn_ack_builds_figure_6(self) -> None:
        """SYN and ACK together select the 16-octet form: section 3.2, figure 6.

        The discriminator against figure 5 is the payload, not just the length: this form
        carries an 8-octet truncated HMAC where the SYN form carries a 4-octet token, so
        a maker that picked the wrong layout would drop the HMAC entirely.

        """
        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_join(syn=True, ack=True, backup=False, addr_id=2,
                         hmac=b'\xCC' * 8, nonce=0xDDDDDDDD)
        data = tcp.info.options[Enum_Option.Multipath_TCP]  # type: ignore[attr-defined]

        self.assertJoinLayout(tcp, MP_JOIN_SYNACK_OCTETS)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
        self.assertEqual(data.length, 16)
        self.assertEqual(data.connection, Enum_Flags.SYN | Enum_Flags.ACK)
        self.assertEqual(data.addr_id, 2)
        self.assertEqual(data.hmac, b'\xCC' * 8)
        self.assertEqual(data.nonce, 0xDDDDDDDD)

    def test_ack_builds_figure_7(self) -> None:
        """ACK without SYN selects the 24-octet form: section 3.2, figure 7.

        This form has no ``Address ID``, no token and no nonce at all -- two octets of
        subtype and reserved bits, then the full 160-bit HMAC -- so it is the layout that
        shares the least with the other two.

        """
        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_join(syn=False, ack=True, hmac=b'\xEE' * 20)
        data = tcp.info.options[Enum_Option.Multipath_TCP]  # type: ignore[attr-defined]

        self.assertJoinLayout(tcp, MP_JOIN_ACK_OCTETS)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
        self.assertEqual(data.length, 24)
        self.assertEqual(data.connection, Enum_Flags.ACK)
        self.assertEqual(data.hmac, b'\xEE' * 20)

    def test_three_layouts_are_three_distinct_lengths(self) -> None:
        """The three forms are 12, 16 and 24 octets -- so one form cannot serve.

        The argument against "just drop the branch": whatever single layout a
        flag-blind maker chose would be wrong for two of the three segment kinds, and
        wrong by a different number of octets each time.

        """
        from pcapkit.const.tcp.option import Option as Enum_Option

        lengths = {
            12: build_join(syn=True, ack=False, addr_id=1, token=1, nonce=1),
            16: build_join(syn=True, ack=True, addr_id=1, hmac=bytes(8), nonce=1),
            24: build_join(syn=False, ack=True, hmac=bytes(20)),
        }

        for expected, tcp in lengths.items():
            with self.subTest(length=expected):
                data = tcp.info.options[Enum_Option.Multipath_TCP]  # type: ignore[attr-defined]
                self.assertEqual(data.length, expected)
                self.assertEqual(len(bytes(tcp)) - 20, expected)  # type: ignore[call-overload]

    def test_neither_syn_nor_ack_raises_protocol_error(self) -> None:
        """A flagless segment gets the library's own error, not a bare ``TypeError``.

        ``_make_mptcp_join`` ends in this ``ProtocolError``, and two things can keep a
        caller from it: construction dying on a missing attribute first, and a
        ``cast('Enum_Flags', 0)`` accumulator leaving ``self._flags`` as a plain ``int``,
        on which ``Enum_Flags.SYN in self._flags`` raises ``TypeError: argument of type
        'int' is not a container or iterable``. Seeding with ``Enum_Flags(0)`` is what
        lets the intended error through.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            build_join(syn=False, ack=False, hmac=bytes(20))

        self.assertIn('invalid flags combination', str(caught.exception))

    def test_a_flagless_segment_without_mp_join_still_builds(self) -> None:
        """The flagless case is only an error *for MP_JOIN*, not for TCP generally.

        The control on the previous case: seeding the accumulator with ``Enum_Flags(0)``
        must not have made a flagless segment invalid in itself, and the flag octet it
        writes must still be zero. ``Enum_Flags(0)`` compares equal to ``0`` and ORs
        exactly as a ``cast('Enum_Flags', 0)`` seed does, so it is a drop-in for every
        combination -- which is what makes the seed safe for the six other flags this
        accumulator handles (``cwr``, ``ece``, ``urg``, ``psh``, ``rst``, ``fin``) as
        well as for SYN and ACK.

        """
        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(syn=False, ack=False, **TCP_HEADER)
        self.assertEqual(bytes(tcp)[13], 0x00, 'no flag octet bit should be set')

        maker = TCP.__new__(TCP)
        maker.make(syn=False, ack=False, **TCP_HEADER)  # type: ignore[arg-type]
        self.assertEqual(maker._flags, 0)  # pylint: disable=protected-access
        self.assertFalse(bool(maker._flags))  # pylint: disable=protected-access
        self.assertEqual(maker._flags | Enum_Flags.SYN, Enum_Flags.SYN)  # pylint: disable=protected-access


class TCPMPTCPJoinRoundTripUnitTests(unittest.TestCase):
    """What the public constructor emits for each layout parses back to itself."""

    def test_each_layout_survives_the_wire(self) -> None:
        """Construct, pack, parse, and get the same values back, for all three forms.

        This is the cycle
        :mod:`tests.protocols.test_option_roundtrip_unit` exercises generically. Asserted
        per layout here
        because that suite drives one case per registry code and so reaches only whichever
        form its fixture's flags select.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        cases = (
            ('SYN', dict(syn=True, ack=False, addr_id=1, token=0xAAAAAAAA,
                         nonce=0xBBBBBBBB), 12),
            ('SYN/ACK', dict(syn=True, ack=True, addr_id=2, hmac=b'\xCC' * 8,
                             nonce=0xDDDDDDDD), 16),
            ('ACK', dict(syn=False, ack=True, hmac=b'\xEE' * 20), 24),
        )

        for label, option, length in cases:
            with self.subTest(form=label):
                built = bytes(build_join(**option))  # type: ignore[arg-type,call-overload]
                data = TCP(built, len(built)).info.options[Enum_Option.Multipath_TCP]

                self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)
                self.assertEqual(data.length, length)

                # And the cycle closes: rebuilding from the parsed data reproduces the
                # octets exactly, which is what ``EXPECTED_FAILURES`` measures.
                again = bytes(TCP(syn=option['syn'], ack=option['ack'],
                                  options=[(Enum_Option.Multipath_TCP, data)],
                                  **TCP_HEADER))
                self.assertEqual(again, built)


class TCPMPTCPJoinStaleFlagsUnitTests(unittest.TestCase):
    """The case that rules out initialising ``_flags`` to zero.

    An instance that has parsed a segment already *has* ``_flags``, so no default value
    would change its behaviour. With the options built before the flags, it builds the
    option for the segment it read rather than the one it is asked to write, and does so
    silently.

    """

    def _parsed_join_syn(self) -> 'object':
        """A ``TCP`` instance that has parsed a real MP_JOIN-SYN segment.

        Returns:
            The instance, whose ``_flags`` is ``SYN`` from the wire.

        """
        from pcapkit.protocols.transport.tcp import TCP

        raw = build_tcp_segment(MP_JOIN_SYN_OCTETS, syn=True, ack=False)
        parsed = TCP(raw, len(raw))
        # Touching ``.info`` is what forces the parse; ``_flags`` is set on the way.
        self.assertEqual(parsed.info.flags.syn, True)  # type: ignore[attr-defined]
        return parsed

    def test_parsed_instance_packs_the_requested_layout(self) -> None:
        """``pack`` on a parsed MP_JOIN-SYN instance emits the ACK form when asked to.

        With the options built first, this produces ``…8010…1e0c 10 00 00000000
        00000000``: an ACK header carrying figure 5's 12-octet SYN option, with the
        caller's 20-octet HMAC discarded and an all-zero token and nonce invented in its
        place. No exception -- which is why this outcome is worse than the
        ``AttributeError`` the same defect produces on a fresh instance, and why a zero
        default is not enough.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        parsed = self._parsed_join_syn()

        octets = parsed.pack(  # type: ignore[attr-defined]
            syn=False, ack=True,
            options=[(Enum_Option.Multipath_TCP,
                      {'subtype': Enum_MPTCPOption.MP_JOIN, 'hmac': b'\xEE' * 20})],
            **TCP_HEADER)

        self.assertEqual(octets[13], 0x10, 'the header must carry ACK, as requested')
        self.assertEqual(octets[20:], MP_JOIN_ACK_OCTETS,
                         'the option must be figure 7, not the parsed segment\'s figure 5')
        self.assertEqual(octets[21], 24)
        self.assertEqual(octets[24:], b'\xEE' * 20,
                         'the HMAC the caller passed must reach the wire')

    def test_make_re_derives_the_flags_on_every_call(self) -> None:
        """``make`` recomputes ``_flags`` per call rather than inheriting the parse's.

        **This case is not a regression guard for #587: it passes with either statement
        order.** It is kept, and named for what it actually establishes, because the
        ordering leans on this property: resolving the flags first is only worth anything
        if what it resolves describes the segment being *built*. If ``make`` instead
        reused a previously stored value, resolving it earlier would only move the same
        wrong flags to an earlier point and the defect above would survive.

        Adding an ``options`` argument would not turn this into a discriminator, which is
        worth recording since it is the obvious thing to try. With the options built
        first, ``make`` assigns ``self._flags`` *after* building them -- so by the time
        ``make`` returns, the attribute holds the new call's flags either way, and only
        the option octets built in between are wrong. The assertion that separates the
        two orders is therefore on those octets, and
        :meth:`test_parsed_instance_packs_the_requested_layout` is the case that makes
        it.

        """
        from pcapkit.const.tcp.flags import Flags as Enum_Flags

        parsed = self._parsed_join_syn()
        self.assertEqual(parsed._flags, Enum_Flags.SYN)  # type: ignore[attr-defined]  # pylint: disable=protected-access

        # NOTE: Through ``make`` itself. ``pack`` makes its header on a copy, so it
        # leaves the parsed ``_flags`` on the instance (#1769).
        parsed.make(syn=False, ack=True, **TCP_HEADER)  # type: ignore[attr-defined]

        self.assertEqual(parsed._flags, Enum_Flags.ACK)  # type: ignore[attr-defined]  # pylint: disable=protected-access
        self.assertNotIn(Enum_Flags.SYN, parsed._flags)  # type: ignore[attr-defined]  # pylint: disable=protected-access

        # And again, to a third combination, so the assertion above cannot be satisfied
        # by a one-off rather than by a per-call derivation.
        parsed.make(syn=True, ack=True, **TCP_HEADER)  # type: ignore[attr-defined]

        self.assertEqual(parsed._flags, Enum_Flags.SYN | Enum_Flags.ACK)  # type: ignore[attr-defined]  # pylint: disable=protected-access


class TCPMakeStatementOrderUnitTests(unittest.TestCase):
    """The ordering itself, pinned so a future refactor cannot silently invert it.

    The behavioural cases above are the ones that matter, but they only fail for MP_JOIN.
    Any option maker that comes to read ``self._flags`` would be broken by the same
    inversion, and would fail somewhere else entirely -- so the order is asserted here
    directly, where the failure message can name the cause.

    """

    def test_flags_are_assigned_before_the_options_are_built(self) -> None:
        """In ``TCP.make``'s source, ``self._flags`` is set before ``_make_tcp_options``."""
        from pcapkit.protocols.transport.tcp import TCP

        source = inspect.getsource(TCP.make)
        assignment = source.index('self._flags = _flag')
        build = source.index('self._make_tcp_options(options')

        self.assertLess(
            assignment, build,
            'TCP.make must assign self._flags before calling _make_tcp_options: the '
            'option makers reached from it read that attribute, and _make_mptcp_join '
            'branches on it to pick between RFC 8684 section 3.2 figures 5, 6 and 7'
        )

    def test_the_offset_still_follows_the_option_build(self) -> None:
        """``offset`` is computed after the options, since it counts their octets.

        The statement that has to *stay* below the option build. Moving it up with the
        flags would make the header's data offset describe an empty option area.

        """
        from pcapkit.protocols.transport.tcp import TCP

        source = inspect.getsource(TCP.make)
        build = source.index('self._make_tcp_options(options')
        offset = source.index('offset = math.ceil')

        self.assertLess(build, offset,
                        'offset must be computed from the options total_length')

    def test_the_flags_accumulator_is_a_real_enum_member(self) -> None:
        """``_flags`` supports the membership tests its readers perform.

        Pinned on the behaviour rather than on the source text, because what the option
        makers need is that ``Enum_Flags.SYN in self._flags`` does not raise for *any*
        flag combination -- including none at all, which is the case
        ``cast('Enum_Flags', 0)`` would leave as a plain ``int``.

        ``make`` is called on a bare ``TCP.__new__(TCP)`` rather than through the
        constructor, and that is load-bearing rather than a shortcut. ``Protocol``'s
        ``__post_init__`` packs *and then re-parses*::

            _data = self.pack(**kwargs)     # -> make(), which sets _flags
            self._info = self.unpack(...)   # -> read(), which sets _flags again

        so a fully constructed instance's ``_flags`` is whatever the **read** path left,
        not what ``make`` computed. Both paths seed ``Enum_Flags(0)`` (#597, #616), but
        the re-parse overwrites what ``make`` assigned either way, and it cannot affect
        option construction, which has already finished by then. Observing ``make``
        alone is the only way to assert on the value the option makers actually see.

        """
        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.protocols.transport.tcp import TCP

        for label, syn, ack in (('none', False, False), ('syn', True, False),
                                ('ack', False, True), ('both', True, True)):
            with self.subTest(flags=label):
                tcp = TCP.__new__(TCP)
                tcp.make(syn=syn, ack=ack, **TCP_HEADER)  # type: ignore[arg-type]
                flags = tcp._flags  # pylint: disable=protected-access

                self.assertIsInstance(flags, Enum_Flags)
                self.assertEqual(Enum_Flags.SYN in flags, syn)
                self.assertEqual(Enum_Flags.ACK in flags, ack)


class TCPMPTCPJoinReadPathUnitTests(unittest.TestCase):
    """The control: the parse path dispatches each layout to its own reader.

    #587 is a defect on the make path only, and its ordering lives inside ``make``. These
    guard the read path rather than #587 itself -- they fail only if reordering
    ``make`` disturbs something it is not supposed to touch.

    """

    def test_all_three_layouts_still_parse(self) -> None:
        """Hand-built figures 5, 6 and 7 each reach their own reader."""
        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        cases = (
            ('figure 5', MP_JOIN_SYN_OCTETS, True, False, 12, Enum_Flags.SYN),
            ('figure 6', MP_JOIN_SYNACK_OCTETS, True, True, 16,
             Enum_Flags.SYN | Enum_Flags.ACK),
            ('figure 7', MP_JOIN_ACK_OCTETS, False, True, 24, Enum_Flags.ACK),
        )

        for label, octets, syn, ack, length, connection in cases:
            with self.subTest(figure=label):
                raw = build_tcp_segment(octets, syn=syn, ack=ack)
                data = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

                self.assertEqual(data.length, length)
                self.assertEqual(data.connection, connection)

    def test_a_flagless_segment_is_rejected_by_the_schema_selector(self) -> None:
        """The read path's own flagless guard fires before the reader.

        ``mptcp_data_selector`` cannot choose an MP_JOIN schema with neither flag set, so
        it raises :exc:`~pcapkit.utilities.exceptions.FieldError` there. That is why
        ``_read_mptcp_join``'s closing ``ProtocolError`` is unreachable from a caller.
        ``read`` seeds ``Enum_Flags(0)`` all the same (#616), as ``make`` does (#597) --
        a ``TypeError`` averted only by a guard in a different file is averted fragilely
        -- so calling the dispatcher directly on a flagless parsed segment reaches its
        ``ProtocolError`` rather than a bare ``TypeError``; see
        :meth:`tests.protocols.transport.test_tcp_udp_unit.TCPUDPUnitTests.test_a_flagless_segment_seeds_its_connection_flags_as_an_enum`.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import FieldError

        raw = build_tcp_segment(MP_JOIN_SYN_OCTETS, syn=False, ack=False)

        with self.assertRaises(FieldError) as caught:
            TCP(raw, len(raw)).info  # pylint: disable=expression-not-assigned

        self.assertIn('invalid flags', str(caught.exception))


class TCPMakeOtherOptionsUnitTests(unittest.TestCase):
    """The other control: options that do not read ``self._flags`` are unaffected.

    The flag resolution sits before a call that reaches every option maker in the
    registry, so the claim that its position matters only to MP_JOIN needs at least one
    witness that is not MP_JOIN.

    """

    def test_a_non_flag_dependent_mptcp_option_is_unchanged(self) -> None:
        """MP_CAPABLE builds the same whatever the flags say.

        It is the sibling subtype with the most in common with MP_JOIN -- same registry,
        same dispatcher, same ``_make_mode_mp`` path -- and it does not consult the
        flags, so its octets must be identical across flag combinations that give MP_JOIN
        three different layouts.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        def capable(syn: 'bool', ack: 'bool') -> 'bytes':
            tcp = TCP(syn=syn, ack=ack,
                      options=[(Enum_Option.Multipath_TCP,
                                {'subtype': Enum_MPTCPOption.MP_CAPABLE,
                                 'skey': 0x0102030405060708})],
                      **TCP_HEADER)
            return bytes(tcp)[20:]

        baseline = capable(True, False)
        self.assertEqual(baseline[0], Enum_Option.Multipath_TCP)
        for syn, ack in ((True, True), (False, True), (False, False)):
            with self.subTest(syn=syn, ack=ack):
                self.assertEqual(capable(syn, ack), baseline)

    def test_a_plain_option_still_sets_the_header_offset(self) -> None:
        """A segment with a non-MPTCP option still counts it in ``offset``.

        The ``offset`` computation is the statement that stays below the option build, so
        this pins that it reads the ``total_length`` the option build produced rather than a
        stale or zero one.

        """
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(syn=True, ack=False,
                  options=[(Enum_Option.Maximum_Segment_Size, {'mss': 1460})],
                  **TCP_HEADER)
        octets = bytes(tcp)

        self.assertEqual(octets[20:24], bytes([0x02, 0x04, 0x05, 0xB4]))
        self.assertEqual((octets[12] >> 4) * 4, 24)
        self.assertEqual(len(octets), 24)


if __name__ == '__main__':
    unittest.main()
