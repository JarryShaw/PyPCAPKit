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
one this suite had no way to see. Sixteen HIP parameters are in exactly that
state today.

The case list and the cycle both live in
:file:`examples/generators/options.py`, next to the generator that turns the
same cases into the ``options-*.pcap`` fixtures, so that the captures and these
assertions can never describe different things. See that module for why the
enumeration is registry-driven and how the per-code arguments were chosen.

What this module adds is the *judgement*: :data:`EXPECTED_FAILURES` records, case
by case, which cycles do not close today and which defect stops each one. A case
absent from that table has to come back ``'OK'``.

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
none of the assertions below has been loosened to make a failing case pass. The
one place where an argument was chosen to route *around* a defect rather than
into it is HIP's ``HIP_COPIES``, which puts two copies of each parameter in a
packet because one is unrepresentable; the defect that forces it is not lost,
:meth:`OptionRoundTripTests.test_a_single_hip_parameter_cannot_be_constructed`
pins it directly.

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

    # Four lambdas read ``pkt['length']`` while packing, but the enclosing
    # ``_make_mptcp_*`` never puts a ``length`` in the packet, so the key is
    # simply absent on the construction path.
    'tcp-mptcp/MP_CAPABLE': Gap(
        'CONSTRUCT', "KeyError: 'length'",
        'pcapkit/protocols/schema/transport/tcp.py:658'),
    'tcp-mptcp/ADD_ADDR': Gap(
        'CONSTRUCT', "KeyError: 'length'",
        'pcapkit/protocols/schema/transport/tcp.py:790'),
    'tcp-mptcp/REMOVE_ADDR': Gap(
        'CONSTRUCT', "KeyError: 'length'",
        'pcapkit/protocols/schema/transport/tcp.py:807'),
    'tcp-mptcp/MP_PRIO': Gap(
        'CONSTRUCT', "KeyError: 'length'",
        'pcapkit/protocols/schema/transport/tcp.py:827'),

    # ``_read_tcp_options`` reads ``schema.kind`` off every option schema, but
    # the nested Multipath TCP subtype schemas do not declare one -- the field
    # belongs to the enclosing option.
    'tcp-mptcp/DSS': Gap(
        'CONSTRUCT', "no attribute 'kind'",
        'pcapkit/protocols/transport/tcp.py:668 -- MPTCPDSS declares no kind'),
    'tcp-mptcp/MP_FAIL': Gap(
        'CONSTRUCT', "no attribute 'kind'",
        'pcapkit/protocols/transport/tcp.py:668 -- MPTCPFallback declares no kind'),
    'tcp-mptcp/MP_FASTCLOSE': Gap(
        'CONSTRUCT', "no attribute 'kind'",
        'pcapkit/protocols/transport/tcp.py:668 -- MPTCPFastclose declares no kind'),

    # ``_make_mptcp_join`` branches on ``self._flags``, which only the parse
    # path ever sets, so the constructor cannot be called at all.
    'tcp-mptcp/MP_JOIN': Gap(
        'CONSTRUCT', "no attribute '_flags'",
        'pcapkit/protocols/transport/tcp.py:2675 -- _make_mptcp_join reads '
        'self._flags, which exists only while parsing'),

    # -- IPv4 -----------------------------------------------------------------

    # ``_make_ipv4_options`` appends a bare enumeration member to the option
    # list as its end-of-list padding, and ``OptionField.pack`` accepts only
    # bytes or a Schema. It fires for every option whose packed length is not a
    # multiple of four, which is what these four have in common. LSR, RR and SSR
    # cannot be brought to a multiple of four by any argument: their length is
    # ``3 + counts * 4``.
    'ipv4-option/LSR': Gap(
        'CONSTRUCT', 'Field options has invalid value',
        'pcapkit/protocols/internet/ipv4.py:1225 and :1252 -- a bare '
        'Enum_OptionNumber.EOOL is appended to the option list'),
    'ipv4-option/RR': Gap(
        'CONSTRUCT', 'Field options has invalid value',
        'pcapkit/protocols/internet/ipv4.py:1225 and :1252'),
    'ipv4-option/SSR': Gap(
        'CONSTRUCT', 'Field options has invalid value',
        'pcapkit/protocols/internet/ipv4.py:1225 and :1252'),
    # SID reaches the same padding branch for a second reason of its own:
    # ``_make_opt_sid`` declares ``length=4`` while ``SIDOption.sid`` is a
    # 32-bit field, so the option packs to six octets (``880400000000``).
    'ipv4-option/SID': Gap(
        'CONSTRUCT', 'Field options has invalid value',
        'pcapkit/protocols/internet/ipv4.py:1683 -- _make_opt_sid declares '
        'length=4 but packs 6 octets, which then trips the :1225 padding branch'),

    # ``_make_opt_ts`` passes ``data=`` where the schema field is ``ts_data``.
    # ``Schema.__init__`` only warns about an unknown field name and carries on,
    # so the value is dropped and the attribute stays bound to the class-level
    # descriptor -- which ``post_process`` then tries to iterate.
    'ipv4-option/TS': Gap(
        'CONSTRUCT', "'ListField' object is not iterable",
        'pcapkit/protocols/internet/ipv4.py:1488 -- data= should be ts_data=, '
        'dropped with UnknownFieldWarning and surfacing at '
        'pcapkit/protocols/schema/internet/ipv4.py:262'),

    # -- Quick-Start, in all three protocols that carry it --------------------

    # ``_make_opt_qs`` returns a bare nested schema, but ``func`` is set only by
    # ``_QSOption.post_process``, which runs on the parse path. Since
    # ``__post_init__`` packs and then re-reads, construction fails.
    #
    # There is a second, independent defect in the same option that this case
    # never reaches, and it is the more serious of the two:
    # ``quick_start_data_selector`` hands the nested schema a hardcoded
    # ``SchemaField(length=5)`` where the schema needs eight octets
    # (type 1 + length 1 + flags 1 + ttl 1 + nonce 4). Measured on a
    # hand-built, well-formed 8-octet IPv4 Quick-Start option
    # ``1908002adeadbee0``: it parses "successfully" with
    # ``SchemaWarning: packet length < 0: -3`` and decodes ``nonce`` as **55**
    # instead of 933982136 -- silent corruption rather than a failure -- and the
    # three unconsumed octets are then read as a further, fabricated option,
    # which makes the enclosing IPv4 packet unparseable. The identical
    # ``SchemaField(length=5)`` is at hopopt.py:224 and ipv6_opts.py:224, with
    # the same measured nonce of 55. Fixing the ``func`` defect alone will not
    # make these cases pass.
    'ipv4-option/QS': Gap(
        'CONSTRUCT', "no attribute 'func'",
        'pcapkit/protocols/internet/ipv4.py:1144 -- func is set only by '
        'post_process; and separately '
        'pcapkit/protocols/schema/internet/ipv4.py:128 -- SchemaField(length=5) '
        'for an 8-octet option, which decodes nonce as 55'),
    'hopopt-option/Quick_Start': Gap(
        'CONSTRUCT', "no attribute 'func'",
        'pcapkit/protocols/internet/hopopt.py:869; and separately '
        'pcapkit/protocols/schema/internet/hopopt.py:224 -- SchemaField(length=5)'),
    'ipv6-opts-option/Quick_Start': Gap(
        'CONSTRUCT', "no attribute 'func'",
        'pcapkit/protocols/internet/ipv6_opts.py:881; and separately '
        'pcapkit/protocols/schema/internet/ipv6_opts.py:224 -- '
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

    # ``IPv6_Route.make`` writes a raw octet count into ``length``, which is an
    # 8-octet-unit field, on the dict and Data paths -- while the bytes and
    # Schema paths divide by eight. The read-side guards then reject it, and
    # those guards compare the unit field against octet counts too, so the
    # RFC-correct value would fail as well.
    # Both fragments are tuples rather than the whole message, because the
    # message itself is defective: these two guards interpolate a bare ``type``
    # into an f-string in a method that has no ``type`` parameter, so the name
    # resolves to the builtin and the detail reads ``[TypeNo <class 'type'>]``
    # (issue #442). Matching the literal rendering would pin that bug into this
    # table and turn it red when #442 is fixed, which says nothing about whether
    # the round trip closes. The stable parts either side of it do pin the site:
    # ``[TypeNo`` occurs at exactly three lines of ``ipv6_route.py`` (:462, :506,
    # :546), against 205 occurrences of ``'invalid format'`` tree-wide.
    'ipv6-route-type/Source_Route': Gap(
        'CONSTRUCT', ('IPv6-Route', '[TypeNo', 'invalid format'),
        'pcapkit/protocols/internet/ipv6_route.py:276 -- length in octets, not '
        'in 8-octet units; guard at :461'),
    'ipv6-route-type/Type_2_Routing_Header': Gap(
        'CONSTRUCT', ('IPv6-Route', '[TypeNo', 'invalid format'),
        'pcapkit/protocols/internet/ipv6_route.py:276; guard at :505'),
    # RPL fails earlier still: ``post_process`` assumes ``addresses`` is bytes,
    # which is true after unpacking and false while packing, where it is still
    # the list the constructor was handed.
    'ipv6-route-type/RPL_Source_Route_Header': Gap(
        'CONSTRUCT', 'does not appear to be an IPv4 or IPv6 address',
        'pcapkit/protocols/schema/internet/ipv6_route.py:156 -- post_process '
        'assumes bytes; it runs on the pack path too, from schema.py:647'),

    # -- Mobility Header ------------------------------------------------------

    # ``CGAParameter``'s nested length callback reads ``pkt['length']``, which
    # is present while packing and absent while unpacking: ``SchemaField.unpack``
    # starts the nested schema with a fresh context whose parent is under
    # ``__packet__``. A CGA extension has no other carrier, so the whole
    # ``MH.__extension__`` registry is unreachable through the public API --
    # every code in it fails here, identically, before its own schema is ever
    # unpacked. That is #445, and it is why all four entries below name one site
    # in ``CGAParameter`` rather than anything in the extensions themselves.
    'mh-extension/Multi_Prefix': Gap(
        'PARSE', "KeyError: 'length'",
        'pcapkit/protocols/schema/internet/mh.py:873 -- #445; needs '
        "pkt['__packet__']['length'] on the unpack path"),
    'mh-extension/Exp_FFFD': Gap(
        'PARSE', "KeyError: 'length'",
        'pcapkit/protocols/schema/internet/mh.py:873 -- #445; needs '
        "pkt['__packet__']['length'] on the unpack path"),
    'mh-extension/Exp_FFFE': Gap(
        'PARSE', "KeyError: 'length'",
        'pcapkit/protocols/schema/internet/mh.py:873 -- #445; needs '
        "pkt['__packet__']['length'] on the unpack path"),
    'mh-extension/Exp_FFFF': Gap(
        'PARSE', "KeyError: 'length'",
        'pcapkit/protocols/schema/internet/mh.py:873 -- #445; needs '
        "pkt['__packet__']['length'] on the unpack path"),

    # -- HIP ------------------------------------------------------------------

    # ``_read_param_*`` and ``_make_param_*`` are found by enumeration member
    # name, so both exist for code 128; but the *schema* registry is keyed by
    # the ``code=`` of the class statement, and ``R1CounterParameter`` declares
    # only 129. So code 128 parses as an ``UnassignedParameter``.
    'hip-parameter/R1_Counter': Gap(
        'PARSE', "no attribute 'counter'",
        'pcapkit/protocols/internet/hip.py:822 -- Parameter.registry[128] is '
        'UnassignedParameter, because R1CounterParameter declares code=129 only'),

    # Sixteen parameters whose ``_read_param_*`` stores a list-valued field as a
    # tuple, which ``_make_param_*`` passes straight back to a ``ListField``
    # that accepts only a list. This is the class of defect the reconstruct step
    # exists to find: each one constructs and parses perfectly.
    **{
        f'hip-parameter/{name}': Gap(
            'RECONSTRUCT', "unsupported type <class 'tuple'>",
            'pcapkit/protocols/schema/schema.py:624 -- _read_param_* returns a '
            'tuple where _make_param_* needs a list')
        for name in (
            'ACK', 'DH_GROUP_LIST', 'HIP_CIPHER', 'NAT_TRAVERSAL_MODE',
            'HIT_SUITE_LIST', 'REG_INFO', 'REG_REQUEST', 'REG_RESPONSE',
            'REG_FAILED', 'TRANSPORT_FORMAT_LIST', 'ESP_TRANSFORM', 'ACK_DATA',
            'ROUTE_DST', 'HIP_TRANSPORT_MODE', 'ROUTE_VIA', 'VIA_RVS',
        )
    },

    # ``_make_param_encrypted`` passes ``cipher=``, which is not a field of
    # ``EncryptedParameter`` -- so the cipher id is dropped with an
    # ``UnknownFieldWarning`` and never reaches the wire. The mismatch itself
    # comes from a second defect in the same parameter: the ``data`` length
    # callback omits the four octets ``reserved`` already consumed out of
    # ``len``, so ``len`` grows by four on every round trip (measured: 4 -> 8).
    'hip-parameter/ENCRYPTED': Gap(
        'MISMATCH', '',
        'pcapkit/protocols/internet/hip.py:3445 -- cipher= is not a field of '
        'EncryptedParameter and is silently dropped; and '
        'pcapkit/protocols/schema/internet/hip.py:463 -- the data length '
        "callback omits the 4 octets 'reserved' took out of len"),

    # Two parameters whose own packed length is not what the header arithmetic
    # can represent even in pairs -- see HIP_COPIES in the generator for why the
    # pair is used at all.
    'hip-parameter/HIP_TRANSFORM': Gap(
        'CONSTRUCT', 'HIPv2: [ParamNo 577] invalid parameter',
        'pcapkit/protocols/internet/hip.py:698 -- the len check; HIP_TRANSFORM '
        'packs to a length the make-side arithmetic cannot express'),
    'hip-parameter/HOST_ID': Gap(
        'CONSTRUCT', 'HIPv2: invalid format',
        'pcapkit/protocols/internet/hip.py:698 -- HOST_ID packs to 14 octets '
        'with len=8, so it is not even 4-aligned'),

    # -- HTTP/2 ---------------------------------------------------------------

    # ``SchemaField.pack`` gives a nested frame schema a fresh packet context
    # whose only link to the parent is ``__packet__``, but six frame schemas
    # reach for the HTTP/2 header's ``flags`` bitfield directly -- either from a
    # ConditionalField test or from ``FrameType.post_process``. The three frames
    # that pass are exactly the three declaring no flag members at all:
    # RST_STREAM, GOAWAY and WINDOW_UPDATE.
    **{
        f'httpv2-frame/{name}': Gap(
            'CONSTRUCT', "KeyError: 'flags'",
            'pcapkit/protocols/schema/application/httpv2.py:144 '
            '(FrameType.post_process) and the pad_len ConditionalField tests at '
            ':175, :204, :305 -- the nested context reaches for the parent '
            "header's flags")
        for name in ('DATA', 'HEADERS', 'SETTINGS', 'PUSH_PROMISE', 'PING',
                     'CONTINUATION')
    },

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

    def test_a_single_hip_parameter_cannot_be_constructed(self) -> None:
        """A HIP packet carrying exactly one parameter is rejected by its own reader.

        This is the defect the generator's ``HIP_COPIES = 2`` routes around, and
        it is pinned here so that routing around it does not also bury it.

        ``HIP.make`` computes the header's ``len`` as ``total_length // 8 + 4``,
        which is lossless only when the parameter octets are a multiple of eight.
        The parameter padding rule pads the *contents* to eight and ignores the
        four-octet type-and-length header, so one parameter is always
        ``4 (mod 8)``; the floor division drops those four octets, and
        ``_read_hip_param`` compares the recovered length exactly and raises.

        Two copies sum to a multiple of eight, so the same parameter that fails
        alone succeeds in a pair -- which is the control that makes this a
        statement about the header arithmetic rather than about ``SEQ``.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        base = dict(self.options.HIP_BASE)
        one = [(Parameter.SEQ, {})]  # type: list[tuple[Any, dict[str, Any]]]

        with self.assertRaises(ProtocolError) as caught:
            HIP(parameters=one, extension=True, **base)
        self.assertIn('invalid format', str(caught.exception))

        # The control: the identical parameter, twice, round-trips exactly.
        paired = bytes(HIP(parameters=one * 2, extension=True, **base))
        reparsed = HIP(paired, len(paired), extension=True)
        again = bytes(HIP(parameters=reparsed.info.parameters, extension=True, **base))
        self.assertEqual(paired, again)

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
