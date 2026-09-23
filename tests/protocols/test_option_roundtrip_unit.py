# -*- coding: utf-8 -*-
"""Construct -> parse -> construct identity, over every option-like code.

Every option, chunk, parameter, message type, frame type and block type this
library claims to support is enumerated *from the dispatch registries* and put
through one cycle: construct it through the public construction API, parse the
result back, construct it again from what was parsed, and require the octets to
be identical across the round trip.

That third step is what this module exists for. A construct-then-parse test
passes for a ``_make_*`` that takes only keyword arguments and cannot consume
the data model its own ``_read_*`` produced -- which is a defect that ships, and
one this suite had no way to see. Sixteen HIP parameters used to be in exactly
that state, until :class:`~pcapkit.protocols.schema.schema.Schema`'s
``ListField`` pack branch was widened to accept the ``tuple`` their own data
models declare, not just ``list``. See #476.

The case list and the cycle both live in
:file:`examples/generators/options.py`, next to the generator that turns the
same cases into the ``options-*.pcap`` fixtures, so that the captures and these
assertions can never describe different things. See that module for why the
enumeration is registry-driven and how the per-code arguments were chosen.

What this module adds is the *judgement*: :data:`EXPECTED_FAILURES` records, case
by case, which cycles do not close today and which defect stops each one. A case
absent from that table has to come back ``'OK'``.

That table can only speak about cycles that *fail*, though, and a defect can
leave the cycle closed -- the generator constructing and reconstructing the same
wrong octets, which match each other and so match the assertion. Those are
pinned as tests of their own rather than as entries, since an entry would have to
record ``'OK'`` as a failure. HIP's parameter padding was the standing example:
it aligned the contents to eight rather than the record, so every parameter was
``4 (mod 8)``, the header ``len`` field could not represent a lone one, and the
generator's ``HIP_COPIES`` put two in a packet to make the arithmetic come out.
A round trip could never see any of it, because pcapkit's writer and reader
shared the error. #651 fixed it against :rfc:`7401` Section 5.2.1 rather than
against a round trip, and
:meth:`OptionRoundTripTests.test_a_hip_packet_carrying_one_parameter_round_trips`
is the same pin, now asserting the case closes.

IPv4's ``SID`` option width was the other one, tracked as #534 and pinned here by
a ``test_a_parsed_sid_option_re_emits_two_octets_too_wide`` that no longer exists:
``SIDOption.sid`` has been narrowed to a 16-bit field, so a four-octet option read
off the wire now re-emits as the same four octets. The assertion that says so is
:meth:`IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire
<tests.protocols.internet.test_ipv4_unit.IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire>`,
in the IPv4 unit suite beside the rest of that option's coverage rather than here
-- what kept it in this module was the ``EXPECTED_FAILURES`` entry it stood in
for, and with the defect fixed there is nothing for it to stand in for.

Why the table is asserted in both directions
--------------------------------------------

An expected failure that is only allowed to fail is a test that rots. So each
entry is checked to still fail, *and* to fail in the recorded way -- so fixing
one of these defects turns this module red, which is the reminder to delete the
entry. The reverse check matters as much: :meth:`test_expected_failures_name_real_cases`
fails if the table names a case that no longer exists, which is what happens when
a registry entry is renamed or removed.

Nothing here is a workaround for the defects it records. Every ``_make_*``
argument in the generator's tables is a legitimate value for that option, and
none of the assertions below has been loosened to make a failing case pass. HIP's
``HIP_COPIES`` used to be the one place where an argument was chosen to route
*around* a defect rather than into it, putting two copies of each parameter in a
packet so a lone one's unrepresentable length never had to be constructed. One
copy has been representable since #651, and by the time #672 and #679 landed the
pair was routing around nothing that a single copy did not already hit -- see the
constant's note in the generator for the measurement -- so #689 dropped it to
one. The single-parameter case is asserted directly by
:meth:`OptionRoundTripTests.test_a_hip_packet_carrying_one_parameter_round_trips`,
which is also where the two-copy shape is still exercised now that this table no
longer produces it.

This module is unit tier: it constructs its own octets and reads no capture, so
it runs on a fresh checkout with nothing generated.

"""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import purge_modules, time_limit
from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any, Optional

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one case may take. Generous next to a working case, which takes
#: low single-digit milliseconds; the point of the deadline is the cases that
#: never finish at all.
CASE_TIMEOUT = 10


class Gap(NamedTuple):
    """One cycle that does not close, and the defect that stops it."""

    #: Expected :attr:`~examples.generators.options.Outcome.status`.
    status: 'str'
    #: Substring the failure detail must contain, or a tuple of substrings *all*
    #: of which it must contain, or ``''`` to assert only the status. Empty is
    #: used where the detail is a pair of long hex strings, or where it embeds a
    #: timestamp and so is not stable between runs.
    #:
    #: Make it as specific as the message allows, because a fragment that matches
    #: half the tree does not pin anything: ``'invalid format'`` alone occurs 205
    #: times across 13 modules (31 in :file:`internet/hip.py`, 26 in
    #: :file:`transport/tcp.py`), so it is satisfied by a regression at any of
    #: them. Prefer the alias and whatever bracketed code the message carries --
    #: ``'TCP: [OptNo 28] invalid format'`` narrows those 26 sites to the one
    #: option that can print ``28``. The tuple form is for messages whose stable
    #: parts are not contiguous, so that a fragment does not have to bake in a
    #: rendering that is itself defective.
    fragment: 'str | tuple[str, ...]'
    #: The defect, named with the ``file:line`` that causes it. This is the
    #: field that makes the entry worth keeping rather than just silencing.
    defect: 'str'


#: Every case whose cycle does not close today.
#:
#: Grouped by defect rather than by family, because the failures cluster far more
#: tightly by cause than by protocol: four lines of ``schema/transport/tcp.py``
#: account for four Multipath TCP subtypes, and one line of
#: ``pcapkit/protocols/misc/pcapng.py`` accounts for twenty-seven PCAP-NG
#: options.
EXPECTED_FAILURES = {

    # -- TCP ------------------------------------------------------------------

    # ``_make_mode_timeout`` writes ``length=3`` into an option that packs to
    # four octets (kind, length, and a two-octet bitfield), and
    # ``_read_mode_timeout`` checks the length exactly. Measured: the schema
    # packs ``1c03003c`` where a correct one is ``1c04003c``.
    'tcp-option/User_Timeout_Option': Gap(
        'CONSTRUCT', 'TCP: [OptNo 28] invalid format',
        'pcapkit/protocols/transport/tcp.py:2506 -- _make_mode_timeout sets '
        'length=3 for a 4-octet option'),

    # ``_make_mode_qs`` computes ``rate_val`` as a floor of a logarithm that is
    # negative for any rate under 40 kbps, and a negative value then fails to
    # pack into the 4-bit field with ``ValueError: invalid literal for int()
    # with base 2: b'0000-110'``. At the default ``rate=0`` it is guarded, and
    # the option constructs -- and then will not parse back.
    'tcp-option/Quick_Start_Response': Gap(
        'PARSE', 'StructError',
        'pcapkit/protocols/transport/tcp.py:2465 -- _make_mode_qs; rate_val is '
        'negative below 40 kbps, and the option it emits at rate=0 does not '
        'parse back'),

    # #541 declared real ``kind``/``length`` fields on ``MPTCP``, which got six
    # of these seven far enough to construct and pack, and #566/#567 closed
    # the rest of the chain: #566 gave ``MPTCP.subtype`` the same treatment
    # (it was ``TYPE_CHECKING``-only, an annotation rather than a field, and
    # the only thing that ever set it was ``_MPTCP.post_process``, which runs
    # on a real byte-level unpack -- not on the schema a ``_make_mptcp_*``
    # maker returns in memory, which is what ``TCP``'s convenience
    # constructor, ``TCP(options=[(code, kwargs)])``, reads straight back
    # through ``_read_mptcp_*`` with no round trip in between); #567 fixed
    # MP_CAPABLE's own ``length``/``rkey`` arithmetic on top of that. Six of
    # the seven (MP_CAPABLE, ADD_ADDR, REMOVE_ADDR, MP_PRIO, DSS, MP_FAIL) now
    # read ``'OK'`` and so have no entry below any more.
    #
    # MP_FASTCLOSE joined them in #576, and its entry is gone with them. Fixing
    # ``subtype`` in #566 had got it *past* the ``AttributeError`` this table
    # used to record and into a second, unrelated defect: three sites disagreed
    # on its length, and the maker's *correct* value (12, from :rfc:`8684`
    # section 3.5 figure 14 -- section 3.5 is Fast Close; the entry that used to
    # sit here cited 3.7, which is Fallback) failed the parser's wrong check of
    # 16, while the schema packed only 11 for want of a reserved octet. All
    # three read 12 now. Note that REMOVE_ADDR, MP_PRIO and DSS in the list
    # above read ``'OK'`` throughout that period *without* being correct -- this
    # suite only checks the cycle is self-consistent, which a wrong length can
    # be, so #576 covers them per option in
    # :mod:`tests.protocols.transport.test_tcp_mptcp_length_arithmetic_unit`
    # against RFC 8684 rather than against the cycle.

    # MP_JOIN was the last of the eight MPTCP subtypes with a registered maker to
    # keep an entry here, recording ``CONSTRUCT`` with ``"no attribute '_flags'"``
    # against ``_make_mptcp_join``. Its entry is gone with #587, which was a
    # statement-ordering defect rather than a length one and so deliberately
    # outlived #576/#585: ``_make_mptcp_join`` branches on ``self._flags`` to
    # choose between the three MP_JOIN layouts of RFC 8684 section 3.2, and
    # ``TCP.make`` assigned that attribute *after* it had already built the
    # options. #587 hoists the flag resolution above the ``_make_tcp_options``
    # call, leaving only the ``offset`` computation -- which genuinely needs the
    # options' ``total_length`` -- after it.
    #
    # The cycle closes for whichever layout this suite's flags select, the SYN
    # form of figure 5, since ``examples.generators.options``' ``TCP_BASE`` sets
    # ``syn`` and leaves ``ack`` clear. The other two forms, and the silent
    # wrong-layout outcome that made a zero-valued default the wrong fix, are
    # covered per layout in
    # :mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit`
    # -- this suite can only ever exercise one MP_JOIN form, there being one
    # case per registry code.

    # -- IPv4, whose option padding is now fixed ------------------------------

    # ``_make_ipv4_options`` used to append a bare enumeration member to the
    # option list as its end-of-list padding, where ``OptionField.pack`` accepts
    # only bytes or a Schema, so every option whose packed length is not a
    # multiple of four failed to construct. #506 appends an ``EOOL`` option
    # *schema* instead, the way the ``NOP`` options beside it always did, so
    # ``LSR``, ``RR`` and ``SSR`` round-trip and have no entry here any more --
    # and they could not have been routed around, their length being
    # ``3 + counts * 4`` and so never a multiple of four for any argument.
    #
    # ``SID`` reached that same branch for a second reason of its own, which #506
    # did not address and #534 now has: ``SIDOption.sid`` was a ``UInt32Field``
    # where RFC 791 section 3.1 gives the Stream ID 16 bits, so the option
    # re-emitted as ``880400000037`` where the wire holds ``88040037``. Six not
    # being a multiple of four, it then reached the padding branch above and grew
    # a ``NOP`` and an ``EOOL``. The field is now ``UInt16Field``, the option
    # re-emits as the four octets it was read as, and the padding branch is not
    # reached at all.
    #
    # Neither state was expressible here. The cycle closed either way, because
    # the generator constructs and reconstructs through the same
    # ``_make_opt_sid`` and so compared six octets against six -- and a ``Gap``
    # naming ``'OK'`` is the one entry
    # :meth:`test_round_trip_is_identity_or_a_recorded_gap` reads as "no entry
    # needed". Which is why the width is asserted against *wire* octets instead,
    # now in :meth:`IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire
    # <tests.protocols.internet.test_ipv4_unit.IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire>`.

    # ``_make_opt_ts`` used to be recorded here too. It passed ``data=`` where the
    # schema field is ``ts_data``; ``Schema.__update__`` only warns about an
    # unknown field name and carries on, so the value was dropped and the
    # attribute stayed bound to the class-level ``ListField`` descriptor -- which
    # ``post_process`` then tried to iterate, ``'ListField' object is not
    # iterable``. The IPv4 Timestamp option was unbuildable through ``make`` for
    # as long as that stood. #552 passes ``ts_data=`` and corrects the
    # ``TYPE_CHECKING`` ``__init__`` stub that advertised ``data`` and is what the
    # maker was written against, so ``ipv4-option/TS`` round-trips and has no
    # entry here any more.

    # -- Quick-Start, in all three protocols that carry it --------------------

    # ``_make_opt_qs`` returns a bare nested schema, but ``func`` is set only by
    # ``_QSOption.post_process``, which runs on the parse path. Since
    # ``__post_init__`` packs and then re-reads, construction fails.
    #
    # There was a second, independent defect in the same option that these cases
    # never reach, and it was the more serious of the two:
    # ``quick_start_data_selector`` handed the nested schema a hardcoded
    # ``SchemaField(length=5)`` where a Quick-Start Request needs eight octets
    # (type 1 + length 1 + flags 1 + ttl 1 + nonce 4). Measured on a
    # hand-built, well-formed 8-octet IPv4 Quick-Start option
    # ``1908002adeadbee0``: it parsed "successfully" with
    # ``SchemaWarning: packet length < 0: -3`` and decoded ``nonce`` as **55**
    # instead of 933982136 -- silent corruption rather than a failure -- and the
    # three unconsumed octets were then read as a further, fabricated option,
    # which made the enclosing IPv4 datagram fail with ``ProtocolError: IPv4:
    # invalid format``.
    #
    # #552 fixed IPv4's copy: the length now comes from
    # ``quick_start_option_length(schema)``, i.e. from the suboption the selector
    # resolved, and ``QuickStartReportOption`` gained the ``Not Used`` octet
    # :rfc:`4782#section-3.1` gives it and it was missing -- it packed seven
    # octets against the ``length=8`` that ``_make_opt_qs`` writes and
    # ``_read_opt_qs`` demands, so a spec-correct Report of Approved Rate read off
    # the wire decoded its nonce one octet early. ``ipv4-option/QS`` is still
    # recorded below because the ``func`` defect is untouched and fails first.
    #
    # The identical ``SchemaField(length=5)`` is still at
    # ``schema/internet/hopopt.py:255`` and ``schema/internet/ipv6_opts.py:255``,
    # with the same measured nonce of 55; #552 was scoped to IPv4's copy. Note a
    # fix there is not a copy of this one: :rfc:`4782#section-3.2` sets the IPv6
    # option's ``length`` field to 6 rather than 8, since it excludes the common
    # type and length octets the extension header already carries. Fixing
    # the ``func`` defect alone will not make any of these three cases pass.
    'ipv4-option/QS': Gap(
        'CONSTRUCT', "no attribute 'func'",
        'pcapkit/protocols/internet/ipv4.py:1178 -- func is set only by '
        'post_process'),
    'hopopt-option/Quick_Start': Gap(
        'CONSTRUCT', "no attribute 'func'",
        'pcapkit/protocols/internet/hopopt.py:918; and separately '
        'pcapkit/protocols/schema/internet/hopopt.py:255 -- SchemaField(length=5)'),
    'ipv6-opts-option/Quick_Start': Gap(
        'CONSTRUCT', "no attribute 'func'",
        'pcapkit/protocols/internet/ipv6_opts.py:921; and separately '
        'pcapkit/protocols/schema/internet/ipv6_opts.py:255 -- '
        'SchemaField(length=5)'),

    # -- The non-progress loop, now fully fixed -------------------------------

    # Both of these used to *hang* rather than fail, which is why the cycle is
    # run under a deadline at all. #432 landed the progress guard in
    # ``OptionField``/``ListField`` and fixed the ``_SMFDPDOption`` sizing in
    # *both* schema modules symmetrically -- 26 lines each, ``'len': (1, 8)`` to
    # ``(8, 8)`` and the ``+ 2`` on the selector's ``SchemaField`` -- so
    # ``hopopt-option/SMF_DPD`` round-trips and has no entry here at all.
    #
    # ``IPv6-Opts`` used to still fail, and not because it missed that fix. The
    # two modules differed in exactly one line of code, older than #432:
    # ``ipv6_opts.SMFIdentificationBasedDPDOption`` declared a second, redundant
    # ``test`` ``ForwardMatchField`` that ``hopopt``'s does not. The enclosing
    # ``_SMFDPDOption`` already has one, in both modules, and it is that outer
    # field the selector reads -- nothing read the nested copy. But a
    # ``ForwardMatchField`` does not consume the stream while still occupying a
    # slot in ``__buffer__``, so the nested schema over-reported its own size by
    # one octet, and ``OptionField`` then mis-counted the option area against
    # the header. Measured on the *same* octets, ``1100080100010100``:
    #
    #     hopopt    __fields__ = [type, len, info, tid, id]        len(schema) = 3
    #     ipv6_opts __fields__ = [type, len, test, info, tid, id]  len(schema) = 4
    #
    #     HOPOPT(...)    -> options=[SMF_DPD, PadN]
    #     IPv6_Opts(...) -> ProtocolError: IPv6-Opts: invalid format
    #
    # This was identical on 3.10.20 and 3.14.7, so it was never
    # interpreter-dependent. Fixed by #441/PR #449, which dropped the stray
    # field -- ``ipv6-opts-option/SMF_DPD`` now round-trips too and has no
    # entry here either.
    #
    # The deadline in the sweep stays regardless. It is protection against the
    # *next* non-progress defect, not against this one.

    # -- IPv6-Route -----------------------------------------------------------

    # ``Source_Route`` and ``Type_2_Routing_Header`` used to be recorded here:
    # ``IPv6_Route.make`` wrote a raw octet count into ``length`` (``Hdr Ext
    # Len``) on the dict and Data paths, a different-and-also-wrong expression
    # on the bytes and Schema paths, and separately, ``ipv6_route_data_selector``
    # (pcapkit/protocols/schema/internet/ipv6_route.py) sized the nested
    # routing-data schema 4 octets short of the wire, missing the "Reserved"
    # field every routing type's data starts with -- so a hand-built,
    # spec-correct header failed to parse independently of anything ``make``
    # produced. #487 fixed both: one shared helper
    # (``IPv6_Route._make_hdr_ext_len``) computes ``Hdr Ext Len`` in the
    # 8-octet units :rfc:`8200#section-4.4` specifies, on every ``make``
    # branch, and ``ipv6_route_data_selector`` accounts for the 4-octet
    # offset. Both cases round-trip now; entries deleted rather than left
    # behind, per the note at the top of this table.

    # ``RPL_Source_Route_Header`` used to be recorded here too, behind a stack
    # of four defects that had to come off in order -- which is why it outlived
    # #487 by several rounds:
    #
    #   1. ``post_process`` assumed ``addresses`` was bytes -- true after
    #      unpacking, false while packing, where it is still the list the
    #      constructor was handed. Fixed by #556, which unmasked the rest.
    #   2. The reader's length guard read ``header.length`` (``Hdr Ext Len``,
    #      in 8-octet units) as an octet count and assumed 16-octet addresses,
    #      which an SRH only carries when ``CmprI`` and ``CmprE`` are both 0 --
    #      the same unit confusion #487 fixed for Source Route and Type 2,
    #      flagged but deliberately left by #489 for want of a working round
    #      trip to validate a replacement against.
    #   3. Behind that, the schema's fixed area -- ``cmpr_i`` + ``cmpr_e`` +
    #      ``pad`` -- packed to 5 octets where :rfc:`6554#section-3` gives 4,
    #      ``CmprI``/``CmprE``/``Pad`` being 4-bit fields sharing one 32-bit
    #      word with a 20-bit ``Reserved``. Measured before the fix: a
    #      constructed header of 41 octets against the 48 its own ``Hdr Ext
    #      Len`` of 5 declared.
    #   4. And behind *that*, once the guard stopped rejecting every
    #      constructed header, ``_read_data_type_rpl`` raised a bare
    #      ``AttributeError`` on the construction path, because
    #      ``post_process`` set ``ip`` only when it had parsed octets.
    #
    # #564 took all four off together -- the guard could not be validated
    # against a header whose width was still wrong -- replacing the ``% 16``
    # bound with :rfc:`6554#section-4.2`'s own address-count arithmetic. The
    # case round-trips now; entry deleted rather than left behind, per the note
    # at the top of this table. The caveat #489 recorded does survive: none of
    # it has been checked against a real RPL capture.

    # -- Mobility Header ------------------------------------------------------
    #
    # ``mh-extension/{Multi_Prefix,Exp_FFFD,Exp_FFFE,Exp_FFFF}`` all round-trip
    # cleanly now that #445, #437 and #446 are all applied together: #445 let
    # ``CGAParameter.extensions`` size itself instead of raising
    # ``KeyError: 'length'``, #437 (merged as registry completion) both
    # registered the three experimental codes and fixed
    # ``_make_ext_multiprefix``'s bogus length arithmetic, and #446/#456 fixed
    # the ``ForwardMatchField`` double-count that stopped ``CGAParametersOption
    # .parameters`` from sizing correctly. No entries needed here any more.

    # -- HIP ------------------------------------------------------------------

    # ``_read_param_*`` and ``_make_param_*`` are found by enumeration member
    # name, so both exist for code 128; but the *schema* registry is keyed by
    # the ``code=`` of the class statement, and ``R1CounterParameter`` declares
    # only 129. So code 128 parses as an ``UnassignedParameter``.
    'hip-parameter/R1_Counter': Gap(
        'PARSE', "no attribute 'counter'",
        'pcapkit/protocols/internet/hip.py:822 -- Parameter.registry[128] is '
        'UnassignedParameter, because R1CounterParameter declares code=129 only'),

    # ``ENCRYPTED`` used to have an entry here, for two defects at once: that
    # ``_make_param_encrypted`` passed ``cipher=``, a keyword
    # ``EncryptedParameter`` does not accept, so the cipher id was dropped with
    # an ``UnknownFieldWarning`` and never reached the wire; and that the
    # ``data`` length callback omitted the four octets ``reserved`` had already
    # taken out of ``len``, so ``len`` grew by four on every round trip
    # (measured: 4 -> 8). The first was fixed by #556. The second was fixed
    # alongside #651, because the two four-octet errors cancelled at four of the
    # eight residues of ``Length`` -- measured, ``Length % 8`` in {0, 5, 6, 7} --
    # so correcting the padding on its own would have turned "right at four
    # residues" into "four octets too long at all eight". With both gone the
    # cycle closes and the entry is deleted rather than kept as documentation of
    # a defect that is no longer there.

    # Two parameters whose own packed length is not what the header arithmetic
    # can represent, even at HIP_COPIES's old value of two -- see that
    # constant's note in the generator for the measurement that dropped it to
    # one without changing either of these.
    'hip-parameter/HIP_TRANSFORM': Gap(
        'CONSTRUCT', 'HIPv2: [ParamNo 577] invalid parameter',
        'pcapkit/protocols/internet/hip.py:698 -- the len check; HIP_TRANSFORM '
        'packs to a length the make-side arithmetic cannot express'),
    'hip-parameter/HOST_ID': Gap(
        'CONSTRUCT', 'HIPv2: invalid format',
        'pcapkit/protocols/internet/hip.py:698 -- HOST_ID packs to 14 octets '
        'with len=8, so it is not even 4-aligned'),

    # -- HTTP/2 ---------------------------------------------------------------

    # ``SchemaField.pack`` used to give a nested frame schema a fresh packet
    # context whose only link to the parent was ``__packet__``, and six frame
    # schemas reach for the HTTP/2 header's ``flags`` bitfield directly --
    # either from a ConditionalField test or from ``FrameType.post_process``.
    # #445 makes a name absent from the nested schema fall through to the
    # parent instead of raising, which fixed that for all six. RST_STREAM,
    # GOAWAY and WINDOW_UPDATE already passed, declaring no flag members at
    # all; the other five each got past ``flags`` and hit their own,
    # unrelated defect in turn -- and every one of those has since been
    # fixed and merged too, so none of the six needs an entry any more:
    #
    # - PUSH_PROMISE, PING: round-tripped cleanly as soon as #445 landed.
    # - DATA, HEADERS, CONTINUATION: hit ``decorators.py``'s ``@prepare``
    #   treating a zero-length nested unpack (a frame with no payload) as
    #   end-of-file. Filed as #458, fixed and merged as #461 (``prepare`` now
    #   distinguishes a *declared* zero length from a *derived* one).
    # - SETTINGS: hit ``SettingsFrame.settings`` declaring
    #   ``item_type=SettingPair`` (the raw schema class) instead of
    #   ``SchemaField(schema=SettingPair)``. Filed as #459, fixed and merged
    #   as #462.

    # ``make`` writes ``length = payload + 9`` and a PRIORITY payload is five
    # octets, so the constructed header always says 14 -- while the reader
    # demands exactly 9. Its siblings all check payload+9 (RST_STREAM 13,
    # WINDOW_UPDATE 13, PING 17), so 9 looks like the outlier.
    'httpv2-frame/PRIORITY': Gap(
        'CONSTRUCT', 'HTTP/2: [Type 2] invalid format',
        'pcapkit/protocols/application/httpv2.py:572 -- reads length != 9 for a '
        'frame make() always builds with length 14'),

    # -- PCAP-NG --------------------------------------------------------------

    # ``PCAPNG.__post_init__`` packs and then re-parses *on the same instance*,
    # and both halves share the per-instance option counter: the make path
    # increments it, the read path then trips its own "only one of these"
    # guard on the option it just built. Twenty-seven options have such a
    # guard; the ten that construct are the ones that do not.
    **{
        f'pcapng-option/{name}': Gap(
            'CONSTRUCT', 'option must be only one',
            'pcapkit/protocols/misc/pcapng.py:1078 packs and :1088 re-parses on '
            'one instance, sharing self._opt; incremented at :3941, checked at '
            ':2175')
        for name in (
            'if_name_2', 'if_description_3', 'if_MACaddr_6', 'if_EUIaddr_7',
            'if_speed_8', 'if_tsresol_9', 'if_tzone_10', 'if_filter_11',
            'if_os_12', 'if_fcslen_13', 'if_tsoffset_14', 'if_hardware_15',
            'if_txspeed_16', 'if_rxspeed_17',
            'epb_flags_2', 'epb_dropcount_4', 'epb_packetid_5', 'epb_queue_6',
            'ns_dnsname_2', 'ns_dnsIP4addr_3', 'ns_dnsIP6addr_4',
            'isb_ifrecv_4', 'isb_ifdrop_5', 'isb_filteraccept_6',
            'isb_osdrop_7', 'isb_usrdeliv_8',
            'pack_flags_2',
        )
    },

    # ``_make_option_if_ipv6`` hardcodes ``length=8``, copied from its IPv4
    # sibling where 8 is right, while ``IPv6InterfaceField`` is 17 octets. The
    # option packs to 21, the block total becomes 41, and no argument the caller
    # can pass changes it.
    'pcapng-option/if_IPv6addr_5': Gap(
        'CONSTRUCT', 'invalid length: 41',
        'pcapkit/protocols/misc/pcapng.py:4190 -- length=8 for a 17-octet '
        'IPv6InterfaceField'),

    # ``_isb_interface_id`` is read by these two make-side constructors but
    # assigned only by ``_read_block_isb``.
    'pcapng-option/isb_starttime_2': Gap(
        'CONSTRUCT', "no attribute '_isb_interface_id'",
        'pcapkit/protocols/misc/pcapng.py:4991 -- reads an attribute set only '
        'at :1790, on the parse path'),
    'pcapng-option/isb_endtime_3': Gap(
        'CONSTRUCT', "no attribute '_isb_interface_id'",
        'pcapkit/protocols/misc/pcapng.py:5024 -- as above'),

    # The three packet-carrying blocks lose their payload on the way back:
    # ``_make_block_*`` never restores ``packet_data``, and it could not, since
    # the data model has no field to keep it in -- the octets go to the
    # next-layer dissector and survive only as the decoded chain. The rebuilt
    # block keeps ``captured_len`` while carrying no data, so it is malformed
    # rather than merely shorter.
    **{
        f'pcapng-block/{name}': Gap(
            'MISMATCH', '',
            'pcapkit/protocols/misc/pcapng.py:3514, :3565, :3851 -- '
            'packet_data is not restored, and '
            'pcapkit/protocols/data/misc/pcapng.py:442, :474, :895 have no '
            'field to restore it from')
        for name in ('Enhanced_Packet_Block', 'Simple_Packet_Block', 'Packet_Block')
    },

    # The two key-log secrets writers terminate each line with ``os.sep`` -- a
    # forward slash on POSIX -- where a newline is meant, while the readers
    # split on newlines. So the whole log parses as one comment line and every
    # entry is lost. They also stamp the current time into the body with no way
    # to override it, which is why these two are the only cases in the suite
    # whose failure detail is not stable, and why the generator's
    # Decryption Secrets Block case uses a ZigBee key instead.
    'pcapng-secrets/TLS_Key_Log': Gap(
        'MISMATCH', '',
        'pcapkit/protocols/misc/pcapng.py:5553 and :5556 -- os.sep as a line '
        'terminator, against splitlines() at '
        'pcapkit/protocols/schema/misc/pcapng.py:1480; and datetime.now() in '
        'the payload'),
    'pcapng-secrets/WireGuard_Key_Log': Gap(
        'MISMATCH', '',
        'pcapkit/protocols/misc/pcapng.py:5585 and :5587, against '
        'pcapkit/protocols/schema/misc/pcapng.py:1519; and datetime.now()'),
}


def _gap_for(label: 'str') -> 'Optional[Gap]':
    """The recorded expectation for ``label``, or :data:`None` if it should pass.

    Args:
        label: Case label, e.g. ``'tcp-mptcp/MP_JOIN'``.

    Returns:
        The recorded :class:`Gap`, or :data:`None` when the case is expected to
        round-trip on this interpreter.

    """
    return EXPECTED_FAILURES.get(label)


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path.

    That directory is not a package, and its module names are too generic to put
    on :data:`sys.path` -- which is exactly why
    :file:`examples/generators/make_samples.py` loads its siblings by path too.
    This follows it.

    Returns:
        The generator module, which exposes ``cases``, ``roundtrip``, ``FAMILIES``
        and ``SKIP``.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location('pcapkit_samples_options', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option case table from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OptionRoundTripTests(unittest.TestCase):
    """One construct -> parse -> construct cycle per registered code."""

    #: The generator module, loaded once for the whole class. Loading it imports
    #: :mod:`pcapkit`, so it must happen after :meth:`setUp` has purged the
    #: previous test's copy -- hence a class attribute filled in
    #: :meth:`setUpClass` rather than a module-level import.
    options = None  # type: Any

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.options = _load_generator()

    def _run(self, case: 'Any') -> 'Any':
        """One cycle, under this suite's deadline rather than the generator's.

        The generator applies its own :func:`signal.alarm` deadline, because
        ``make samples`` must not hang either. Letting both arm the alarm would
        break the outer one: the inner context cancels the pending alarm on the
        way out, which is the outer deadline's countdown. So the generator's is
        switched off here and :func:`tests._support.time_limit` owns the clock,
        which is what the rest of the suite uses.

        Args:
            case: The case to exercise.

        Returns:
            The cycle's outcome, with a timeout reported as ``'TIMEOUT'`` rather
            than raised, so that it is asserted on like any other failure.

        """
        try:
            with time_limit(CASE_TIMEOUT):
                return self.options.roundtrip(case, deadline=0)
        except TimeoutError as exc:
            return self.options.Outcome(case, 'TIMEOUT', str(exc), None, ())

    def test_every_registered_code_has_a_case(self) -> None:
        """No registry entry is left without a case.

        This is what makes the coverage self-maintaining. Registering a new
        option and forgetting to exercise it fails here, rather than going
        unnoticed until the option turns out not to construct.

        """
        for family in self.options.FAMILIES:
            with self.subTest(family=family.label):
                registry = family.registry()
                covered = {case.code for case in self.options.cases((family,))}
                skipped = {
                    code for code in registry
                    if (family.label, self.options.code_name(code)) in self.options.SKIP
                }
                self.assertEqual(
                    set(registry), covered | skipped,
                    f'{family.label}: every code in the registry needs a case in '
                    f'examples/generators/options.py, or an entry in its SKIP table'
                )

    def test_every_registered_code_resolves_without_growing_the_registry(self) -> None:
        """Each code resolves to a handler, and asking does not mutate the registry.

        Two things at once, because they are the same lookup.

        A registry entry naming a handler that does not exist is a live bug that
        nothing else catches: dispatch falls through to the fallback and the
        option is quietly parsed as unassigned. Two of the ``MH`` registries'
        own docstrings name prefixes that were never implemented
        (``_read_option_*`` and ``_read_extension_*``, where the code uses
        ``_read_opt_*`` and ``_read_ext_*``), so the hazard is not theoretical.

        And every one of these registries is a :class:`collections.defaultdict`
        on a class attribute, so a lookup that misses *inserts*, permanently, for
        the whole process. The sizes are compared either side to prove the
        non-recording path was used.

        """
        for family in self.options.FAMILIES:
            with self.subTest(family=family.label):
                registry = family.registry()
                before = len(registry)

                for code in list(registry):
                    resolved = self.options.handler(registry, code)
                    self.assertIsNotNone(
                        resolved,
                        f'{family.label}: {self.options.code_name(code)} resolves '
                        f'to nothing'
                    )

                self.assertEqual(
                    len(registry), before,
                    f'{family.label}: the registry grew while being read; a '
                    f'lookup went through registry[code] instead of '
                    f'ProtocolBase._lookup_registry'
                )

    def test_expected_failures_name_real_cases(self) -> None:
        """Both tables name only cases that exist.

        Without this they rot silently: a renamed or removed registry entry
        leaves behind an entry that can never be checked, and which then reads as
        documentation of a defect nobody can find.

        """
        labels = {case.label for case in self.options.cases()}
        stale = sorted(set(EXPECTED_FAILURES) - labels)
        self.assertEqual(
            stale, [],
            f'these entries of EXPECTED_FAILURES name cases that no longer '
            f'exist; delete them, or fix the label'
        )

    def test_round_trip_is_identity_or_a_recorded_gap(self) -> None:
        """Every case either closes the cycle, or fails exactly as recorded.

        Both halves matter. A case absent from :data:`EXPECTED_FAILURES` must
        come back ``'OK'``; a case present in it must still fail, and with the
        recorded status and detail, so that fixing the defect turns this red and
        the entry gets deleted rather than left behind.

        """
        cases = self.options.cases()
        self.assertGreater(len(cases), 200,
                           'the registries should yield a few hundred codes; a '
                           'much smaller number means the enumeration broke')

        for case in cases:
            with self.subTest(case=case.label):
                outcome = self._run(case)
                gap = _gap_for(case.label)

                if gap is None:
                    self.assertEqual(
                        outcome.status, 'OK',
                        f'{case.label} no longer round-trips: {outcome.detail}. '
                        f'If this is a newly found defect, add it to '
                        f'EXPECTED_FAILURES with the file:line that causes it -- '
                        f'do not change the case to avoid it.'
                    )
                    continue

                self.assertEqual(
                    outcome.status, gap.status,
                    f'{case.label} was recorded as failing with '
                    f'{gap.status} ({gap.defect}) but came back '
                    f'{outcome.status}: {outcome.detail}. If the defect is fixed, '
                    f'delete its EXPECTED_FAILURES entry.'
                )
                fragments = ((gap.fragment,) if isinstance(gap.fragment, str)
                             else gap.fragment)
                for fragment in fragments:
                    if not fragment:
                        continue
                    self.assertIn(
                        fragment, outcome.detail,
                        f'{case.label} still fails with {gap.status}, but not in '
                        f'the recorded way ({gap.defect}); detail was '
                        f'{outcome.detail!r}'
                    )

    def test_a_hip_packet_carrying_one_parameter_round_trips(self) -> None:
        """A HIP packet carrying exactly one parameter is accepted by its own reader.

        This assertion used to run the other way, as
        ``test_a_single_hip_parameter_cannot_be_constructed``: it required the
        library to *reject* its own single-parameter packets, which it did, and
        pinned the defect the generator's ``HIP_COPIES`` (then ``2``) routed
        around so that routing around it did not also bury it.

        ``HIP.make`` computes the header's ``len`` as ``total_length // 8 + 4``,
        which is lossless only when the parameter octets are a multiple of eight.
        Every padding site in the two HIP modules aligned the *contents* to
        eight and ignored the four-octet type-and-length header, so one
        parameter was always ``4 (mod 8)``; the floor division dropped those four
        octets and ``_read_hip_param``, which compares the recovered length
        exactly, raised. #651 made the padding :rfc:`7401` Section 5.2.1's
        ``Total Length = 11 + Length - (Length + 3) % 8``, under which a lone
        parameter is 8-aligned by construction, so the case now closes and this
        test says so positively rather than recording the raise.

        Both halves of the old test are kept, because the pair was its control:
        one copy and two copies must *both* work, and must both come back as the
        octets they went out as. ``SEQ`` is the case that discriminates hardest,
        at ``Length = 4``: the record needs no padding at all
        (``11 + 4 - (4 + 3) % 8 == 8``), so the old rule's four appended octets
        were pure surplus rather than a shortfall, and a reader that pads by any
        non-zero amount lands in the wrong place at the start of the second copy.

        ``HIP_COPIES`` dropped to ``1`` in #689, once #672 and #679 had closed
        the last two codes a second copy was still routing around -- see the
        constant's note in the generator. That makes the ``copies=1`` subtest
        below redundant with the main sweep, which now exercises
        ``hip-parameter/SEQ`` at exactly one copy itself; it is kept anyway
        because it pins the exact wire layout (``len(built)``, the header's
        ``len`` byte, the reparsed count) rather than only the round-trip
        identity the sweep checks. The ``copies=2`` subtest is no longer
        redundant with anything -- the generator does not build that shape any
        more -- so this is the one place left that still asserts the pair
        round-trips.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        base = dict(self.options.HIP_BASE)
        one = [(Parameter.SEQ, {})]  # type: list[tuple[Any, dict[str, Any]]]

        for copies in (1, 2):
            with self.subTest(copies=copies):
                built = bytes(HIP(parameters=one * copies, extension=True, **base))

                # 40 octets of fixed header, then one 8-octet SEQ per copy --
                # the RFC total for Length = 4, and what the header's own
                # ``len`` field can represent exactly.
                self.assertEqual(len(built), 40 + 8 * copies)
                self.assertEqual(built[1], 4 + copies)

                reparsed = HIP(built, len(built), extension=True)
                self.assertEqual(
                    len(reparsed.info.parameters.getlist(Parameter.SEQ)), copies)

                again = bytes(HIP(parameters=reparsed.info.parameters,
                                  extension=True, **base))
                self.assertEqual(built, again)

    def test_recorded_gaps_are_a_minority(self) -> None:
        """Most of the option space round-trips, and the rest is accounted for.

        A guard on the shape of the result rather than on any one case: if a
        change makes the failures outnumber the successes, something systemic
        broke and the per-case assertions above will be too noisy to read.

        """
        total = len(self.options.cases())
        recorded = len(EXPECTED_FAILURES)
        self.assertLess(
            recorded, total // 2,
            f'{recorded} of {total} cases are recorded as failing; that is more '
            f'than half, which suggests the harness rather than the library is at '
            f'fault'
        )


if __name__ == '__main__':
    unittest.main()
