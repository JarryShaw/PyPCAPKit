# -*- coding: utf-8 -*-
"""Regression tests for GitHub issue #775's tier 1: the miss path must not mint.

The ruling on #775 is that no registry creates a registered enum out of an
unrecognised or unregistered value, however legitimate but unbounded the values
are, unless the user or caller explicitly created it -- and lookup never counts as
asking for a name, only the new :meth:`register` classmethod does. Before this change, both ``get()``'s string
path and ``_missing_``'s bounded-but-unassigned range branch called
:func:`aenum.extend_enum`, permanently growing the registry for a value nobody
asked to be named. Measured on this tree before the fix:
:class:`~pcapkit.const.arp.hardware.Hardware`'s ``__members__`` moved from 41
entries to 42 after a single ``Hardware(40)`` (40 sits in the documented
39-255 "Unassigned" range) and stayed at 42 on a second call -- growth that
never reverses for the life of the process, and that a long-running capture
walking many such values would accumulate without bound.

Tier 1 touches exactly two sites in :mod:`pcapkit.vendor.default`: the shared
``get()`` template and the ``_missing_`` range-branch :meth:`~pcapkit.vendor.
default.Vendor.process` assembles -- see that module for the two hunks. It is
scoped to the registries that inherit both unmodified, which this module's
:data:`REGISTRIES_WITH_UNASSIGNED_RANGES` and :data:`ALL_REGISTRIES` enumerate;
the 12 vendor files that replace the shared template wholesale (and whatever
they generate) are out of scope and untouched.

Tier 1 fixed the *mechanism* (a lookup should never mint); it did not decide,
registry by registry, which of the remaining ``_missing_`` bodies mint
something worth keeping. That is tier 2; the owner's mint/unmint criterion was
settled on PR #847 and confirmed on #775 as the core of the ruling: a name
is minted when it is the final concrete name an assignment gave, and left
unminted when it is only a notation for the readers. A dynamically or statically
assigned range is as unspecified as any other -- it gets concrete names when
something assigns them -- so its placeholder is notation, not a name worth
registering. Applied registry by registry to every ``_missing_`` that still called
:func:`~aenum.extend_enum` -- measured
at exactly 89 modules by an AST walk over ``pcapkit/const/*.py`` (not the
"~92" an earlier pass in this programme estimated) -- the ruling converted 82
of them outright (172 branches, :data:`RULING_CONVERTED_REGISTRIES` below),
left :class:`~pcapkit.const.reg.ethertype.EtherType` and
:class:`~pcapkit.const.ipx.socket.Socket` *mixed* (each keeps some branches
minting and converts others -- see :data:`ETHERTYPE_UNASSIGNED_PROBES` and
:data:`IPX_SOCKET_UNASSIGNED_PROBES`), and left 9 classes across 6 files
untouched because they do not inherit :class:`~pcapkit.corekit.enum.
EnumRegistry` and so have no ``_unregistered_member`` to convert to until
GitHub issue #860 lands (blocked on #859); :class:`~pcapkit.const.reg.
apptype.apptype.AppType` is the largest of those at 766 still-minting
branches. :class:`~pcapkit.const.mh.cga_type.CGAType` keeps minting too, but
for a different reason: its ``Tag_<hex>`` mint is not an IANA-style
range at all (see its own module for why), so the ruling never touched it.

GitHub issue #860 (step 2, PR 1) has now brought 8 of those 9 classes onto
:class:`~pcapkit.corekit.enum.EnumRegistry` and converted their branches --
15 in total, see :data:`BESPOKE_UNMINT_CONVERTED_REGISTRIES` and
:class:`BespokeOpenVocabularyUnmintConvertedTests` below. Two distinct
shapes:

Five range-bounded registries whose old mint used a manufactured
placeholder label (``Unassigned``, ``Unknown_%d``, ``opt_unknown_%d``):
:class:`~pcapkit.const.http.status_code.StatusCode` (8),
:class:`~pcapkit.const.ftp.return_code.ReturnCode`,
:class:`~pcapkit.const.ftp.return_code.ResponseKind` and
:class:`~pcapkit.const.ftp.return_code.GroupingInformation` (1 each), and
:class:`~pcapkit.const.pcapng.option_type.OptionType` (1) -- 12 branches,
unambiguous under the mint/unmint criterion from the first measurement.
Each carries a custom ``__new__`` with extra per-member attributes (unlike
any of the 82 tier-2 registries above), so each needed its own
``_unregistered_member`` override reconstructing those attributes rather
than the shared base's generic one, and two of the five
(:class:`StatusCode`, :class:`ReturnCode`) had their own hand-written
``get()`` replaced by the base's -- see :class:`BespokeGetReplacementTests`
for the ``default == -1`` -> ``NO_DEFAULT`` behaviour change that implies.
:class:`OptionType` keeps its own ``get()`` (genuine multi-namespace
dispatch the base does not replicate), but round 2 review found that
``get()`` still minted on both its int/namespace path and its ``str`` path
-- the same "leaving ``get()`` minting while ``_missing_`` does not
contradicts the ruling" argument that converted :class:`Command`'s and
:class:`Method`'s own ``get()`` mint sites below, just missed the first
time round for the third registry that has one. Both are now
``_unregistered_member`` calls too; see
:meth:`BespokeUnmintConvertedRegistriesTests.
test_optiontype_get_int_path_no_longer_mints`,
``..._namespace_path_...`` and ``..._str_path_...``.

Three open-vocabulary registries whose old mint used the exact, unmodified
observed value as its own name rather than any manufactured label:
:class:`~pcapkit.const.ftp.command.FEATCode`,
:class:`~pcapkit.const.ftp.command.Command` and
:class:`~pcapkit.const.http.method.Method` -- 1 ``_missing_`` branch each,
initially left minting pending the owner's ruling (this measurement's own
report flagged them as genuinely ambiguous under the criterion, since
nothing about them is a manufactured placeholder). GitHub issue #860 is
where the owner settled it: ``get()`` must not mint, because only
``register()`` creates a new registry entry -- for these three registries
only IANA-registered values are legitimate, and ``get()`` does not have
enough information to construct one itself. That rule is about ``get()``
in its own right, and it extends just as much to
``_missing_`` -- :class:`Command` needs ``feat``/``desc``/``type``/``conf``
and :class:`Method` needs ``safe``/``idempotent``, neither of which a bare
wire string carries -- so both classes' own ``get()`` (a second, independent
mint site bypassing ``_missing_`` entirely) converts too, alongside
``_missing_``; :class:`FEATCode` has no custom ``__new__``, and had no
``get()`` of its own at the time either, so only its one ``_missing_`` branch
was in play. (It has one now -- GitHub issue #903's audit gave it a
case-insensitive ``get`` per :rfc:`5797#section-2` -- but that override never
calls ``cls(key)``, so it added no mint site to this file's concern.)

GitHub issue #860 step 2's PR 2 has now converted the last of the 9:
:class:`~pcapkit.const.reg.apptype.apptype.AppType` and its four per-transport
registries (:class:`~pcapkit.const.reg.apptype.tcp.TCP`,
:class:`~pcapkit.const.reg.apptype.udp.UDP`,
:class:`~pcapkit.const.reg.apptype.sctp.SCTP`,
:class:`~pcapkit.const.reg.apptype.dccp.DCCP`) now mix in
:class:`~pcapkit.corekit.enum.EnumRegistry` and no longer mint on either of
AppType's two mint sites -- the 766 ``_missing_`` branches, and the one more
inside ``get()`` itself. See :class:`AppTypeUnmintConvertedTests` below,
including the deliberate scope decision on the 8 of those 766 branches that
name a real (if IANA-assigned to a whole span rather than declared
individually) service rather than a placeholder.

Untouched, per the owner's ruling on #860 settling the ``needs: decision`` that
issue re-opened: :class:`~pcapkit.const.ftp.command.CommandType` keeps
``IntFlag``, because that is how the RFC/IANA data is constructed and ``|`` may
appear in the CSV -- measured, 2 occurrences in
the generated data join two kinds with ``/`` and would break under a plain
``IntEnum``; see :class:`BespokeOpenVocabularyUnmintConvertedTests`'s own
``test_commandtype_is_untouched``.
:class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`, by contrast,
*did* change -- on a different ruling than CommandType's, not the same one.
GitHub PR #836 is what first retired ``|``-composite decoding: once
``TransportProtocol`` is no longer a ``Flag``, a ``|``-joined value is not parsed
and accepted but treated as a whole, instead of being split. GitHub issue #860
later drew the further consequence once nothing decoded a composite any more:
the power-of-two spacing existed only for the ``tcp | udp``-style code that
composition served, and since the new logic does not accept that piping, ``auto()``
is the expected numbering. So it now numbers its five members sequentially from
0 -- ``undefined`` a direct, explicit ``0``, the rest continuing from it
via ``auto()`` with no ``_start_`` needed, per the owner's own further
ruling settling the declaration shape -- rather than by the power-of-two
spacing that composition used to need. The owner also ruled, on #860, that no
test should pin the one behavioural consequence, since it is an obsolete path
left by an accepted breaking change -- and it is a real consequence,
not a refusal: a hand-composed ``tcp | udp`` (or a bare, uncomposed ``3``)
now silently resolves as ``sctp``'s own value through
:meth:`AppType._dispatch`, where it used to name no registry at all and
raise. None of the tests below pin that, per the same ruling.

GitHub issue #775's final round closes the two mixed registries themselves:
every one of :class:`~pcapkit.const.reg.ethertype.EtherType`'s 52
still-minting range branches, and :class:`~pcapkit.const.ipx.socket.Socket`'s
one (``Registered by Xerox``), now convert to
:meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` too -- PR #878
scoped it this way: keeping the existing hex-suffixed name, since this change
is about not registering rather than renaming. So each keeps the hex-suffixed
name it always rendered (``Xyplex_0x0888``, not a bare ``Xyplex``) even though
it no longer registers -- neither is "mixed" any more, both are wholly
converted like the 82 in :data:`RULING_CONVERTED_REGISTRIES`, and
:class:`EtherTypeMixedMintTests`/:class:`IPXSocketMixedMintTests` below are
retitled in place to prove the formerly-kept probe no longer mints rather than
that it still does. The one consequence worth naming: this reintroduces the
exact "manufactured, value-suffixed name" shape :func:`is_manufactured` exists
to flag, on calls that are still safe because :meth:`_unregistered_member`
never registers regardless of what its ``name`` argument looks like -- see
:func:`_is_hex_suffixed_unregistered_name` in
:class:`UnregisteredMemberNameIsBareTests` for the scoped exemption this
required, keyed on the ``name`` argument's own shape rather than on the two
files it happens to live in today.

"""
from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import re
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._support import (ISOLATED_PREFIXES, purge_modules, reimport_once_per_class,
                            restore_modules, snapshot_modules)

if TYPE_CHECKING:
    from typing import Optional

#: (module, class name) for every one of tier 1's 22 registries whose vendor
#: crawler inherits :mod:`pcapkit.vendor.default`'s ``process()`` unmodified,
#: so their ``_missing_`` range branches are in scope for the mint fix too --
#: not just their ``get()``. Derived by AST from pcapkit/vendor/*.py: these are
#: exactly the in-scope vendor files with no ``def process`` override of their
#: own.
REGISTRIES_WITH_UNASSIGNED_RANGES = (
    ('pcapkit.const.arp.hardware', 'Hardware'),
    ('pcapkit.const.arp.operation', 'Operation'),
    ('pcapkit.const.hip.certificate', 'Certificate'),
    ('pcapkit.const.hip.cipher', 'Cipher'),
    ('pcapkit.const.hip.di', 'DITypes'),
    ('pcapkit.const.hip.ecdsa_curve', 'ECDSACurve'),
    ('pcapkit.const.hip.ecdsa_low_curve', 'ECDSALowCurve'),
    ('pcapkit.const.hip.esp_transform_suite', 'ESPTransformSuite'),
    ('pcapkit.const.hip.hi_algorithm', 'HIAlgorithm'),
    ('pcapkit.const.hip.hit_suite', 'HITSuite'),
    ('pcapkit.const.hip.nat_traversal', 'NATTraversal'),
    ('pcapkit.const.hip.notify_message', 'NotifyMessage'),
    ('pcapkit.const.hip.registration', 'Registration'),
    ('pcapkit.const.hip.registration_failure', 'RegistrationFailure'),
    ('pcapkit.const.hip.suite', 'Suite'),
    # NOTE: hip.transport.Transport is deliberately absent here: its FLAG
    # bound (0-3) covers every defined code with no unassigned gap, so its
    # process() emits no range branch at all -- nothing for this sweep to
    # exercise. It still carries get()/register()/_unregistered_member,
    # which ALL_REGISTRIES below covers.
    ('pcapkit.const.ospf.authentication', 'Authentication'),
    ('pcapkit.const.ospf.packet', 'Packet'),
    ('pcapkit.const.sctp.cause_code', 'CauseCode'),
    ('pcapkit.const.sctp.chunk', 'Chunk'),
    ('pcapkit.const.sctp.parameter', 'Parameter'),
    ('pcapkit.const.sctp.payload_protocol_identifier', 'PayloadProtocolIdentifier'),
)

#: Adds the one range-less registry back in, for the tests that only need
#: get()/register()/_unregistered_member rather than an unassigned value.
ALL_REGISTRIES = REGISTRIES_WITH_UNASSIGNED_RANGES + (
    ('pcapkit.const.hip.transport', 'Transport'),
)

#: Every one of tier 1's 105 registries -- every generated ``const/`` module
#: whose vendor crawler inherits the shared ``get()``/``register()``/
#: ``_unregistered_member()`` template from :mod:`pcapkit.vendor.default`
#: unmodified. Derived the same way as :data:`ALL_REGISTRIES` above, just
#: without narrowing to the 22 with an unassigned range: every vendor file
#: under :mod:`pcapkit.vendor` that is not one of the 12 which replace the
#: shared template wholesale (and not one of the four ``AppType`` transport
#: subclasses that inherit *that* bespoke template instead).
ALL_105_REGISTRIES = (
    ('pcapkit.const.arp.hardware', 'Hardware'),
    ('pcapkit.const.arp.operation', 'Operation'),
    ('pcapkit.const.esp.cipher', 'Cipher'),
    ('pcapkit.const.esp.integrity', 'Integrity'),
    ('pcapkit.const.hip.certificate', 'Certificate'),
    ('pcapkit.const.hip.cipher', 'Cipher'),
    ('pcapkit.const.hip.di', 'DITypes'),
    ('pcapkit.const.hip.ecdsa_curve', 'ECDSACurve'),
    ('pcapkit.const.hip.ecdsa_low_curve', 'ECDSALowCurve'),
    ('pcapkit.const.hip.eddsa_curve', 'EdDSACurve'),
    ('pcapkit.const.hip.esp_transform_suite', 'ESPTransformSuite'),
    ('pcapkit.const.hip.group', 'Group'),
    ('pcapkit.const.hip.hi_algorithm', 'HIAlgorithm'),
    ('pcapkit.const.hip.hit_suite', 'HITSuite'),
    ('pcapkit.const.hip.nat_traversal', 'NATTraversal'),
    ('pcapkit.const.hip.notify_message', 'NotifyMessage'),
    ('pcapkit.const.hip.packet', 'Packet'),
    ('pcapkit.const.hip.parameter', 'Parameter'),
    ('pcapkit.const.hip.registration', 'Registration'),
    ('pcapkit.const.hip.registration_failure', 'RegistrationFailure'),
    ('pcapkit.const.hip.suite', 'Suite'),
    ('pcapkit.const.hip.transport', 'Transport'),
    ('pcapkit.const.http.error_code', 'ErrorCode'),
    ('pcapkit.const.http.frame', 'Frame'),
    ('pcapkit.const.http.setting', 'Setting'),
    ('pcapkit.const.ipv4.classification_level', 'ClassificationLevel'),
    ('pcapkit.const.ipv4.option_class', 'OptionClass'),
    ('pcapkit.const.ipv4.option_number', 'OptionNumber'),
    ('pcapkit.const.ipv4.protection_authority', 'ProtectionAuthority'),
    ('pcapkit.const.ipv4.qs_function', 'QSFunction'),
    ('pcapkit.const.ipv4.router_alert', 'RouterAlert'),
    ('pcapkit.const.ipv4.tos_del', 'ToSDelay'),
    ('pcapkit.const.ipv4.tos_ecn', 'ToSECN'),
    ('pcapkit.const.ipv4.tos_pre', 'ToSPrecedence'),
    ('pcapkit.const.ipv4.tos_rel', 'ToSReliability'),
    ('pcapkit.const.ipv4.tos_thr', 'ToSThroughput'),
    ('pcapkit.const.ipv4.ts_flag', 'TSFlag'),
    ('pcapkit.const.ipv6.option', 'Option'),
    ('pcapkit.const.ipv6.option_action', 'OptionAction'),
    ('pcapkit.const.ipv6.qs_function', 'QSFunction'),
    ('pcapkit.const.ipv6.router_alert', 'RouterAlert'),
    ('pcapkit.const.ipv6.routing', 'Routing'),
    ('pcapkit.const.ipv6.seed_id', 'SeedID'),
    ('pcapkit.const.ipv6.smf_dpd_mode', 'SMFDPDMode'),
    ('pcapkit.const.ipv6.tagger_id', 'TaggerID'),
    ('pcapkit.const.ipx.packet', 'Packet'),
    ('pcapkit.const.ipx.socket', 'Socket'),
    ('pcapkit.const.l2tp.type', 'Type'),
    ('pcapkit.const.mh.access_type', 'AccessType'),
    ('pcapkit.const.mh.ack_status_code', 'ACKStatusCode'),
    ('pcapkit.const.mh.ani_suboption', 'ANISuboption'),
    ('pcapkit.const.mh.auth_subtype', 'AuthSubtype'),
    ('pcapkit.const.mh.binding_error', 'BindingError'),
    ('pcapkit.const.mh.binding_revocation', 'BindingRevocation'),
    ('pcapkit.const.mh.cga_extension', 'CGAExtension'),
    ('pcapkit.const.mh.cga_sec', 'CGASec'),
    ('pcapkit.const.mh.cga_type', 'CGAType'),
    ('pcapkit.const.mh.dhcp_support_mode', 'DHCPSupportMode'),
    ('pcapkit.const.mh.dns_status_code', 'DNSStatusCode'),
    ('pcapkit.const.mh.dsmip6_tls_packet', 'DSMIP6TLSPacket'),
    ('pcapkit.const.mh.dsmipv6_home_address', 'DSMIPv6HomeAddress'),
    ('pcapkit.const.mh.enumerating_algorithm', 'EnumeratingAlgorithm'),
    ('pcapkit.const.mh.fb_ack_status', 'FlowBindingACKStatus'),
    ('pcapkit.const.mh.fb_action', 'FlowBindingAction'),
    ('pcapkit.const.mh.fb_indication_trigger', 'FlowBindingIndicationTrigger'),
    ('pcapkit.const.mh.fb_type', 'FlowBindingType'),
    ('pcapkit.const.mh.flow_id_status', 'FlowIDStatus'),
    ('pcapkit.const.mh.flow_id_suboption', 'FlowIDSuboption'),
    ('pcapkit.const.mh.handoff_type', 'HandoffType'),
    ('pcapkit.const.mh.handover_ack_status', 'HandoverACKStatus'),
    ('pcapkit.const.mh.handover_initiate_status', 'HandoverInitiateStatus'),
    ('pcapkit.const.mh.home_address_reply', 'HomeAddressReply'),
    ('pcapkit.const.mh.lla_code', 'LLACode'),
    ('pcapkit.const.mh.lma_mag_suboption', 'LMAControlledMAGSuboption'),
    ('pcapkit.const.mh.mn_group_id', 'MNGroupID'),
    ('pcapkit.const.mh.mn_id_subtype', 'MNIDSubtype'),
    ('pcapkit.const.mh.operator_id', 'OperatorID'),
    ('pcapkit.const.mh.option', 'Option'),
    ('pcapkit.const.mh.packet', 'Packet'),
    ('pcapkit.const.mh.qos_attribute', 'QoSAttribute'),
    ('pcapkit.const.mh.revocation_status_code', 'RevocationStatusCode'),
    ('pcapkit.const.mh.revocation_trigger', 'RevocationTrigger'),
    ('pcapkit.const.mh.status_code', 'StatusCode'),
    ('pcapkit.const.mh.traffic_selector', 'TrafficSelector'),
    ('pcapkit.const.mh.upa_status', 'UpdateNotificationACKStatus'),
    ('pcapkit.const.mh.upn_reason', 'UpdateNotificationReason'),
    ('pcapkit.const.ospf.authentication', 'Authentication'),
    ('pcapkit.const.ospf.packet', 'Packet'),
    ('pcapkit.const.pcapng.block_type', 'BlockType'),
    ('pcapkit.const.pcapng.filter_type', 'FilterType'),
    ('pcapkit.const.pcapng.hash_algorithm', 'HashAlgorithm'),
    ('pcapkit.const.pcapng.record_type', 'RecordType'),
    ('pcapkit.const.pcapng.secrets_type', 'SecretsType'),
    ('pcapkit.const.pcapng.verdict_type', 'VerdictType'),
    ('pcapkit.const.reg.ethertype', 'EtherType'),
    ('pcapkit.const.reg.linktype', 'LinkType'),
    ('pcapkit.const.reg.transtype', 'TransType'),
    ('pcapkit.const.sctp.cause_code', 'CauseCode'),
    ('pcapkit.const.sctp.chunk', 'Chunk'),
    ('pcapkit.const.sctp.parameter', 'Parameter'),
    ('pcapkit.const.sctp.payload_protocol_identifier', 'PayloadProtocolIdentifier'),
    ('pcapkit.const.tcp.checksum', 'Checksum'),
    ('pcapkit.const.tcp.mp_tcp_option', 'MPTCPOption'),
    ('pcapkit.const.tcp.option', 'Option'),
    ('pcapkit.const.vlan.priority_level', 'PriorityLevel'),
)

_RANGE_RE = re.compile(r'if (\d+) <= value <= (\d+):')


def _first_unassigned_value(cls: 'type') -> 'int':
    """The first value :meth:`cls._missing_ <object._missing_>`'s own source
    documents as a bounded-but-unassigned range, read from the class's own
    compiled ``_missing_`` rather than hardcoded, so this sweep tracks
    whatever the generated module actually says.

    """
    source = inspect.getsource(cls._missing_)  # type: ignore[attr-defined]
    match = _RANGE_RE.search(source)
    assert match is not None, f'{cls.__name__}._missing_ has no range branch'
    return int(match.group(1))


#: (module, class name) for every one of the 82 registries the owner's
#: #775/#847 ruling converted outright: every ``_missing_`` branch that used
#: to mint via :func:`~aenum.extend_enum` now returns :meth:`~pcapkit.corekit.
#: enum.EnumRegistry._unregistered_member` instead, because what it minted was
#: a bare status word (``Unassigned``, ``Reserved [...]``, ``Reserved for
#: Private/Experimental Use``, ``Unspecified in the IANA registry``, and
#: similar) rather than a name anyone assigned. Derived from the same AST walk
#: that measured 89 modules still minting on ``main`` before this change: 82
#: of the 89 are here, including the two *mixed* registries (:class:`~pcapkit.
#: const.reg.ethertype.EtherType` and :class:`~pcapkit.const.ipx.socket.
#: Socket`, which convert some branches and keep minting others -- see
#: :data:`ETHERTYPE_UNASSIGNED_PROBES` and :data:`IPX_SOCKET_UNASSIGNED_
#: PROBES`). The other 7 of the 89 are untouched: 6 files on classes that do
#: not inherit :class:`EnumRegistry` yet and so have no ``_unregistered_
#: member`` to convert to (:class:`~pcapkit.const.reg.apptype.apptype.
#: AppType`, :class:`~pcapkit.const.http.status_code.StatusCode`, :mod:
#: `pcapkit.const.ftp.return_code`, :mod:`pcapkit.const.ftp.command`,
#: :class:`~pcapkit.const.http.method.Method`, :class:`~pcapkit.const.pcapng.
#: option_type.OptionType` -- see the module docstring), plus :class:
#: `~pcapkit.const.mh.cga_type.CGAType`, which the ruling never touched
#: because its mint is not an IANA-style range at all.
RULING_CONVERTED_REGISTRIES = (
    ('pcapkit.const.esp.cipher', 'Cipher'),
    ('pcapkit.const.esp.integrity', 'Integrity'),
    ('pcapkit.const.hip.eddsa_curve', 'EdDSACurve'),
    ('pcapkit.const.hip.group', 'Group'),
    ('pcapkit.const.hip.packet', 'Packet'),
    ('pcapkit.const.hip.parameter', 'Parameter'),
    ('pcapkit.const.http.error_code', 'ErrorCode'),
    ('pcapkit.const.http.frame', 'Frame'),
    ('pcapkit.const.http.setting', 'Setting'),
    ('pcapkit.const.ipv4.classification_level', 'ClassificationLevel'),
    ('pcapkit.const.ipv4.option_class', 'OptionClass'),
    ('pcapkit.const.ipv4.option_number', 'OptionNumber'),
    ('pcapkit.const.ipv4.protection_authority', 'ProtectionAuthority'),
    ('pcapkit.const.ipv4.qs_function', 'QSFunction'),
    ('pcapkit.const.ipv4.router_alert', 'RouterAlert'),
    ('pcapkit.const.ipv4.tos_del', 'ToSDelay'),
    ('pcapkit.const.ipv4.tos_ecn', 'ToSECN'),
    ('pcapkit.const.ipv4.tos_pre', 'ToSPrecedence'),
    ('pcapkit.const.ipv4.tos_rel', 'ToSReliability'),
    ('pcapkit.const.ipv4.tos_thr', 'ToSThroughput'),
    ('pcapkit.const.ipv4.ts_flag', 'TSFlag'),
    ('pcapkit.const.ipv6.option', 'Option'),
    ('pcapkit.const.ipv6.option_action', 'OptionAction'),
    ('pcapkit.const.ipv6.qs_function', 'QSFunction'),
    ('pcapkit.const.ipv6.router_alert', 'RouterAlert'),
    ('pcapkit.const.ipv6.routing', 'Routing'),
    ('pcapkit.const.ipv6.seed_id', 'SeedID'),
    ('pcapkit.const.ipv6.smf_dpd_mode', 'SMFDPDMode'),
    ('pcapkit.const.ipv6.tagger_id', 'TaggerID'),
    ('pcapkit.const.ipx.packet', 'Packet'),
    ('pcapkit.const.l2tp.type', 'Type'),
    ('pcapkit.const.mh.access_type', 'AccessType'),
    ('pcapkit.const.mh.ack_status_code', 'ACKStatusCode'),
    ('pcapkit.const.mh.ani_suboption', 'ANISuboption'),
    ('pcapkit.const.mh.auth_subtype', 'AuthSubtype'),
    ('pcapkit.const.mh.binding_error', 'BindingError'),
    ('pcapkit.const.mh.binding_revocation', 'BindingRevocation'),
    ('pcapkit.const.mh.cga_extension', 'CGAExtension'),
    ('pcapkit.const.mh.cga_sec', 'CGASec'),
    ('pcapkit.const.mh.dhcp_support_mode', 'DHCPSupportMode'),
    ('pcapkit.const.mh.dns_status_code', 'DNSStatusCode'),
    ('pcapkit.const.mh.dsmip6_tls_packet', 'DSMIP6TLSPacket'),
    ('pcapkit.const.mh.dsmipv6_home_address', 'DSMIPv6HomeAddress'),
    ('pcapkit.const.mh.enumerating_algorithm', 'EnumeratingAlgorithm'),
    ('pcapkit.const.mh.fb_ack_status', 'FlowBindingACKStatus'),
    ('pcapkit.const.mh.fb_action', 'FlowBindingAction'),
    ('pcapkit.const.mh.fb_indication_trigger', 'FlowBindingIndicationTrigger'),
    ('pcapkit.const.mh.fb_type', 'FlowBindingType'),
    ('pcapkit.const.mh.flow_id_status', 'FlowIDStatus'),
    ('pcapkit.const.mh.flow_id_suboption', 'FlowIDSuboption'),
    ('pcapkit.const.mh.handoff_type', 'HandoffType'),
    ('pcapkit.const.mh.handover_ack_status', 'HandoverACKStatus'),
    ('pcapkit.const.mh.handover_initiate_status', 'HandoverInitiateStatus'),
    ('pcapkit.const.mh.home_address_reply', 'HomeAddressReply'),
    ('pcapkit.const.mh.lla_code', 'LLACode'),
    ('pcapkit.const.mh.lma_mag_suboption', 'LMAControlledMAGSuboption'),
    ('pcapkit.const.mh.mn_group_id', 'MNGroupID'),
    ('pcapkit.const.mh.mn_id_subtype', 'MNIDSubtype'),
    ('pcapkit.const.mh.operator_id', 'OperatorID'),
    ('pcapkit.const.mh.option', 'Option'),
    ('pcapkit.const.mh.packet', 'Packet'),
    ('pcapkit.const.mh.qos_attribute', 'QoSAttribute'),
    ('pcapkit.const.mh.revocation_status_code', 'RevocationStatusCode'),
    ('pcapkit.const.mh.revocation_trigger', 'RevocationTrigger'),
    ('pcapkit.const.mh.status_code', 'StatusCode'),
    ('pcapkit.const.mh.traffic_selector', 'TrafficSelector'),
    ('pcapkit.const.mh.upa_status', 'UpdateNotificationACKStatus'),
    ('pcapkit.const.mh.upn_reason', 'UpdateNotificationReason'),
    ('pcapkit.const.pcapng.block_type', 'BlockType'),
    ('pcapkit.const.pcapng.filter_type', 'FilterType'),
    ('pcapkit.const.pcapng.hash_algorithm', 'HashAlgorithm'),
    ('pcapkit.const.pcapng.record_type', 'RecordType'),
    ('pcapkit.const.pcapng.secrets_type', 'SecretsType'),
    ('pcapkit.const.pcapng.verdict_type', 'VerdictType'),
    ('pcapkit.const.reg.ethertype', 'EtherType'),
    ('pcapkit.const.reg.linktype', 'LinkType'),
    ('pcapkit.const.reg.transtype', 'TransType'),
    ('pcapkit.const.tcp.checksum', 'Checksum'),
    ('pcapkit.const.tcp.mp_tcp_option', 'MPTCPOption'),
    ('pcapkit.const.tcp.option', 'Option'),
    ('pcapkit.const.vlan.priority_level', 'PriorityLevel'),
)

#: Subset of :data:`RULING_CONVERTED_REGISTRIES` whose converted branch a
#: generic "first branch that converts, by source order" probe can actually
#: exercise -- i.e. the registry's own bounds contain at least one value that
#: is not already a declared member, *and* nothing earlier in the same
#: ``_missing_`` masks it. One reason holds registries out of this list: 13
#: have no reachable gap at all -- the same situation :data:`ALL_REGISTRIES`
#: already documents for :class:`~pcapkit.const.hip.transport.Transport`:
#: every value inside the guard's own bounds names a real member, so
#: ``_missing_`` can never actually run for them (e.g. :class:`~pcapkit.const.
#: ipv4.tos_del.ToSDelay` is bounded to ``0 <= value <= 1`` and both 0 and 1
#: are declared). They are proved by :class:`RulingConversionSourceTests` (a
#: source sweep) instead.
#:
#: :class:`~pcapkit.const.reg.ethertype.EtherType` used to be held out for a
#: second, distinct reason on top of those 13: its *first* converted branch by
#: source order ("Old Xerox Experimental...", 0x0101-0x01FF) was itself
#: unreachable, masked by the wider 0x0000-0x05DC branch before it, so a naive
#: probe would have silently exercised the wrong branch. GitHub issue #862
#: (fixed by #865) reordered :meth:`pcapkit.vendor.reg.ethertype.EtherType.
#: process` so the narrower range is tested first, which makes that branch
#: directly probeable like any other reachable-gap registry -- the same shape
#: :class:`~pcapkit.const.ipx.socket.Socket` (mixed at the time) already
#: demonstrates in this list below. EtherType has therefore joined this set;
#: see :data:`ETHERTYPE_UNASSIGNED_PROBES`'s comment for the probe itself,
#: still covered explicitly by :class:`EtherTypeMixedMintTests` as well.
#: Neither registry is actually mixed any more as of #775's final round --
#: see that class's own updated docstring.
#:
#: Derived the same way as :data:`RULING_CONVERTED_REGISTRIES`: computed once
#: by walking each candidate's own bounds for a gap, not hand-picked.
RULING_CONVERTED_WITH_REACHABLE_GAP = (
    ('pcapkit.const.esp.cipher', 'Cipher'),
    ('pcapkit.const.esp.integrity', 'Integrity'),
    ('pcapkit.const.hip.eddsa_curve', 'EdDSACurve'),
    ('pcapkit.const.hip.group', 'Group'),
    ('pcapkit.const.hip.packet', 'Packet'),
    ('pcapkit.const.hip.parameter', 'Parameter'),
    ('pcapkit.const.http.error_code', 'ErrorCode'),
    ('pcapkit.const.http.frame', 'Frame'),
    ('pcapkit.const.http.setting', 'Setting'),
    ('pcapkit.const.ipv4.classification_level', 'ClassificationLevel'),
    ('pcapkit.const.ipv4.option_number', 'OptionNumber'),
    ('pcapkit.const.ipv4.qs_function', 'QSFunction'),
    ('pcapkit.const.ipv4.router_alert', 'RouterAlert'),
    ('pcapkit.const.ipv4.ts_flag', 'TSFlag'),
    ('pcapkit.const.ipv6.option', 'Option'),
    ('pcapkit.const.ipv6.qs_function', 'QSFunction'),
    ('pcapkit.const.ipv6.router_alert', 'RouterAlert'),
    ('pcapkit.const.ipv6.routing', 'Routing'),
    ('pcapkit.const.ipv6.tagger_id', 'TaggerID'),
    ('pcapkit.const.ipx.packet', 'Packet'),
    ('pcapkit.const.ipx.socket', 'Socket'),
    ('pcapkit.const.mh.access_type', 'AccessType'),
    ('pcapkit.const.mh.ack_status_code', 'ACKStatusCode'),
    ('pcapkit.const.mh.ani_suboption', 'ANISuboption'),
    ('pcapkit.const.mh.auth_subtype', 'AuthSubtype'),
    ('pcapkit.const.mh.binding_error', 'BindingError'),
    ('pcapkit.const.mh.binding_revocation', 'BindingRevocation'),
    ('pcapkit.const.mh.cga_extension', 'CGAExtension'),
    ('pcapkit.const.mh.cga_sec', 'CGASec'),
    ('pcapkit.const.mh.dns_status_code', 'DNSStatusCode'),
    ('pcapkit.const.mh.dsmip6_tls_packet', 'DSMIP6TLSPacket'),
    ('pcapkit.const.mh.dsmipv6_home_address', 'DSMIPv6HomeAddress'),
    ('pcapkit.const.mh.enumerating_algorithm', 'EnumeratingAlgorithm'),
    ('pcapkit.const.mh.fb_ack_status', 'FlowBindingACKStatus'),
    ('pcapkit.const.mh.fb_action', 'FlowBindingAction'),
    ('pcapkit.const.mh.fb_indication_trigger', 'FlowBindingIndicationTrigger'),
    ('pcapkit.const.mh.fb_type', 'FlowBindingType'),
    ('pcapkit.const.mh.flow_id_status', 'FlowIDStatus'),
    ('pcapkit.const.mh.flow_id_suboption', 'FlowIDSuboption'),
    ('pcapkit.const.mh.handoff_type', 'HandoffType'),
    ('pcapkit.const.mh.handover_ack_status', 'HandoverACKStatus'),
    ('pcapkit.const.mh.handover_initiate_status', 'HandoverInitiateStatus'),
    ('pcapkit.const.mh.home_address_reply', 'HomeAddressReply'),
    ('pcapkit.const.mh.lla_code', 'LLACode'),
    ('pcapkit.const.mh.lma_mag_suboption', 'LMAControlledMAGSuboption'),
    ('pcapkit.const.mh.mn_group_id', 'MNGroupID'),
    ('pcapkit.const.mh.mn_id_subtype', 'MNIDSubtype'),
    ('pcapkit.const.mh.operator_id', 'OperatorID'),
    ('pcapkit.const.mh.option', 'Option'),
    ('pcapkit.const.mh.packet', 'Packet'),
    ('pcapkit.const.mh.qos_attribute', 'QoSAttribute'),
    ('pcapkit.const.mh.revocation_status_code', 'RevocationStatusCode'),
    ('pcapkit.const.mh.revocation_trigger', 'RevocationTrigger'),
    ('pcapkit.const.mh.status_code', 'StatusCode'),
    ('pcapkit.const.mh.traffic_selector', 'TrafficSelector'),
    ('pcapkit.const.mh.upa_status', 'UpdateNotificationACKStatus'),
    ('pcapkit.const.mh.upn_reason', 'UpdateNotificationReason'),
    ('pcapkit.const.pcapng.block_type', 'BlockType'),
    ('pcapkit.const.pcapng.filter_type', 'FilterType'),
    ('pcapkit.const.pcapng.hash_algorithm', 'HashAlgorithm'),
    ('pcapkit.const.pcapng.record_type', 'RecordType'),
    ('pcapkit.const.pcapng.secrets_type', 'SecretsType'),
    ('pcapkit.const.pcapng.verdict_type', 'VerdictType'),
    ('pcapkit.const.reg.ethertype', 'EtherType'),
    ('pcapkit.const.reg.linktype', 'LinkType'),
    ('pcapkit.const.reg.transtype', 'TransType'),
    ('pcapkit.const.tcp.checksum', 'Checksum'),
    ('pcapkit.const.tcp.mp_tcp_option', 'MPTCPOption'),
    ('pcapkit.const.tcp.option', 'Option'),
)

#: :class:`~pcapkit.const.reg.ethertype.EtherType` probes for the owner's
#: original #775/#847 ruling: ``DEC Unassigned`` and the historical list's own
#: "Old Xerox Experimental values. Invalid as an Ethertype since 1983." both
#: convert, because the label itself says nothing was assigned. Every *other*
#: named block -- companies the historical list attributes a real code range
#: to -- used to stay a mint; :data:`ETHERTYPE_FORMERLY_KEPT_PROBE` pins one
#: (``Xyplex``) as a regression guard, now flipped to prove it no longer
#: mints either, since #775's final round converts every remaining branch.
#:
#: "Old Xerox Experimental" (0x0101-0x01FF) used to not be behaviourally
#: probeable: it was a strict subset of the earlier, wider "IEEE802.3 Length
#: Field" branch (0x0000-0x05DC), which the ``_missing_`` if-chain matched
#: first and so masked it completely -- the same shape of ordering bug GitHub
#: issue #841 found in :mod:`pcapkit.const.ipx.socket`, present on ``main``
#: before this change and not part of #775/#847's ruling, so it was left as a
#: follow-up rather than reordered as part of that ruling. GitHub issue #862
#: is that follow-up, fixed by #865: :meth:`pcapkit.vendor.reg.ethertype.
#: EtherType.process` now tests the narrower Old Xerox range before the wider
#: IEEE802.3 one, so 0x0101 resolves to Old Xerox and is directly probeable --
#: it is included below alongside ``DEC Unassigned``, giving it the same
#: behavioural no-mint proof :class:`EtherTypeMixedMintTests` already gives
#: DEC Unassigned, rather than the weaker source-text check that stood in for
#: it before #865 (an order-insensitive string search that would keep passing
#: even if the ordering regressed).
ETHERTYPE_OLD_XEROX_LABEL = 'Old_Xerox_Experimental_values_Invalid_as_an_Ethertype_since_1983'
ETHERTYPE_UNASSIGNED_PROBES = {
    0x8039: 'DEC_Unassigned',
    0x0101: ETHERTYPE_OLD_XEROX_LABEL,
}
#: The one probe the original ruling kept minting -- Xyplex, 0x0888 -- because
#: a proprietary protocol has no public name of its own, so the company name
#: serves as one (#775, #847). #775's final round converts it too, preserving
#: the hex-suffixed name exactly as the crawler always rendered it (PR #878
#: scoped it this way: keeping the existing hex-suffixed name, since this
#: change is about not registering rather than renaming), so this now pins the
#: opposite of what its name suggests: that the formerly-kept probe no longer
#: mints either. Kept as its own constant, distinct from
#: :data:`ETHERTYPE_UNASSIGNED_PROBES`, because
#: :class:`EtherTypeMixedMintTests` below still wants it named individually in
#: its own regression test.
ETHERTYPE_FORMERLY_KEPT_PROBE = (0x0888, 'Xyplex_0x0888')

#: :class:`~pcapkit.const.ipx.socket.Socket` probes for the owner's original
#: #775/#847 ruling: ``Experimental`` and the three dynamically/statically
#: assigned labels convert, as notation for the reader rather than a final
#: concrete assigned name; ``Registered by Xerox``, the company one, used to
#: keep minting, pinned by :data:`IPX_SOCKET_FORMERLY_KEPT_PROBE`.
IPX_SOCKET_UNASSIGNED_PROBES = {
    0x0025: 'Experimental',
    0x4001: 'Dynamically Assigned Socket Numbers',
    0x8001: 'Statically Assigned Socket Numbers',
    0x0BBA: 'Dynamically Assigned',
}
#: The mirror of :data:`ETHERTYPE_FORMERLY_KEPT_PROBE` for
#: :class:`~pcapkit.const.ipx.socket.Socket`: ``Registered by Xerox`` also
#: converts in #775's final round, keeping its hex-suffixed name.
IPX_SOCKET_FORMERLY_KEPT_PROBE = (0x0010, 'Registered by Xerox_0x0010')


def _first_unregistered_value(cls: 'type') -> 'Optional[int]':
    """The first value :meth:`cls._missing_ <object._missing_>` converts to a
    throwaway :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
    pseudo-member, read from the class's own compiled ``_missing_`` by AST
    rather than hardcoded.

    Handles both shapes tier 2 produced: a per-range branch (``if lo <= value
    <= hi: ... return cls._unregistered_member(...)``), whose lower bound is
    the probe; and an unconditional mint straight after the guard (no range
    branch of its own), for which any in-bounds value not already a member
    will do -- so this scans forward from the guard's own lower bound for the
    first gap. Returns :data:`None` if neither shape is reachable at all
    (every in-bounds value is already a declared member), which
    :data:`RULING_CONVERTED_WITH_REACHABLE_GAP` excludes from behavioural
    testing for exactly that reason.

    """
    source = inspect.getsource(cls._missing_)  # type: ignore[attr-defined]
    tree = ast.parse(textwrap.dedent(source))
    func = tree.body[0]

    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        calls_unreg = any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == '_unregistered_member'
            for n in ast.walk(node)
        )
        if not calls_unreg:
            continue
        test = node.test
        if isinstance(test, ast.Compare) and len(test.ops) == 2:
            return ast.literal_eval(test.left)  # type: ignore[no-any-return]

    bounds = None
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner = test.operand
            if isinstance(inner, ast.BoolOp) and isinstance(inner.op, ast.And):
                for value in inner.values:
                    if isinstance(value, ast.Compare) and len(value.ops) == 2:
                        bounds = (ast.literal_eval(value.left), ast.literal_eval(value.comparators[-1]))
                        break
        if bounds is not None:
            break
    if bounds is None:
        return None
    lo, hi = bounds
    for probe in range(lo, min(hi, lo + 100000) + 1):
        if probe not in cls._value2member_map_:  # type: ignore[attr-defined]
            return probe
    return None


def _purge_member(cls: 'type', name: 'str', value: 'int') -> 'None':
    """Undo an :func:`~aenum.extend_enum` so a test's explicit
    :meth:`register` call does not leak into the rest of the suite.

    Mirrors ``tests.const.test_const_apptype_split_unit._purge_member``, minus
    the :class:`~pcapkit.const.reg.apptype.AppType`-only ``__registry__``
    bookkeeping: the base template these registries share carries no such
    attribute.

    """
    member = cls.__members__.get(name)  # type: ignore[attr-defined]
    if member is None:
        return
    cls._member_map_.pop(name, None)  # type: ignore[attr-defined]
    if name in cls._member_names_:  # type: ignore[attr-defined]
        cls._member_names_.remove(name)  # type: ignore[attr-defined]
    cls._value2member_map_.pop(value, None)  # type: ignore[attr-defined]


class UnassignedRangeDoesNotMintTests(unittest.TestCase):
    """A bounded-but-unassigned value must not grow the registry."""

    if TYPE_CHECKING:
        registries: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.registries = [
            getattr(importlib.import_module(module_name), class_name)
            for module_name, class_name in REGISTRIES_WITH_UNASSIGNED_RANGES
        ]
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_the_reported_case(self) -> None:
        """The exact figures from this module's own docstring, pinned."""
        from pcapkit.const.arp.hardware import Hardware

        before = len(Hardware.__members__)
        first = Hardware(40)
        after_one = len(Hardware.__members__)
        second = Hardware(40)
        after_two = len(Hardware.__members__)

        self.assertEqual(before, after_one)
        self.assertEqual(before, after_two)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertNotIn(40, Hardware._value2member_map_)  # type: ignore[attr-defined]
        self.assertNotIn('Unassigned', Hardware.__members__)

    def test_unassigned_value_absent_from_lookup_tables(self) -> None:
        """Swept across every registry with a bounded-unassigned range."""
        for cls in self.registries:
            with self.subTest(registry=cls.__qualname__):
                value = _first_unassigned_value(cls)
                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]

                member = cls(value)

                self.assertEqual(member.value, value)
                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]
                self.assertNotIn(member.name, cls.__members__)

    def test_repeated_lookup_does_not_grow_members(self) -> None:
        """Calling twice must not mint a second permanent member either."""
        for cls in self.registries:
            with self.subTest(registry=cls.__qualname__):
                value = _first_unassigned_value(cls)
                before = len(cls.__members__)

                first = cls(value)
                after_one = len(cls.__members__)
                second = cls(value)
                after_two = len(cls.__members__)

                self.assertEqual(before, after_one)
                self.assertEqual(before, after_two)
                self.assertEqual(first, second)
                self.assertIsNot(first, second)

    def test_out_of_bound_value_still_fails(self) -> None:
        """#775 accepts that a value outside every declared range stays
        failing -- this fix only stops the *mint*, not the eventual raise."""
        from pcapkit.const.arp.hardware import Hardware

        with self.assertRaises(ValueError):
            Hardware(1 << 32)


class GetNoLongerMintsTests(unittest.TestCase):
    """``get()``'s string path must resolve without minting, matching the
    same ruling applied to the int path above."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_unresolvable_string_key_without_default_raises(self) -> None:
        from pcapkit.const.arp.hardware import Hardware

        before = len(Hardware.__members__)
        with self.assertRaises(KeyError):
            Hardware.get('Definitely-Not-A-Member')
        self.assertEqual(before, len(Hardware.__members__))

    def test_unresolvable_string_key_with_default_falls_back_by_value(self) -> None:
        from pcapkit.const.arp.hardware import Hardware

        before = len(Hardware.__members__)
        result = Hardware.get('Definitely-Not-A-Member', 1)
        self.assertIs(result, Hardware.Ethernet)
        self.assertEqual(before, len(Hardware.__members__))

    def test_unresolvable_string_key_with_default_in_unassigned_range(self) -> None:
        """The fallback is itself a value lookup (GitHub issue #864), so a
        default landing in a bounded-unassigned range no longer returns the
        pseudo-member the int path does -- it simply does not resolve, and
        the original key's own error propagates instead. Before #864 this
        resolved via ``cls(default)`` -> ``_missing_`` to an unregistered
        pseudo-member; that is exactly the cost the owner accepted on #864 in
        choosing a value-only lookup: a default naming a value with no
        registered member stops resolving, on every registry, where it used
        to return an unregistered member via ``_missing_``."""
        from pcapkit.const.arp.hardware import Hardware

        before = len(Hardware.__members__)
        with self.assertRaises(KeyError) as caught:
            Hardware.get('Definitely-Not-A-Member', 40)
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(Hardware.__members__))
        self.assertNotIn('Definitely-Not-A-Member', Hardware.__members__)


class RegisterStillMintsTests(unittest.TestCase):
    """The one caller-named, explicit path must still grow the registry."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_register_mints_a_real_permanent_member(self) -> None:
        from pcapkit.const.arp.hardware import Hardware

        self.addCleanup(_purge_member, Hardware, 'PyPCAPKit_775_test', 60000)

        before = len(Hardware.__members__)
        new = Hardware.register(60000, 'PyPCAPKit_775_test')
        after = len(Hardware.__members__)

        self.assertEqual(after, before + 1)
        self.assertIs(new, Hardware.PyPCAPKit_775_test)  # type: ignore[attr-defined]
        self.assertIs(Hardware(60000), new)
        self.assertIn(60000, Hardware._value2member_map_)  # type: ignore[attr-defined]

    def test_register_is_present_on_every_tier_1_registry(self) -> None:
        for module_name, class_name in ALL_REGISTRIES:
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)
                self.assertTrue(callable(getattr(cls, 'register', None)))
                self.assertTrue(callable(getattr(cls, '_unregistered_member', None)))

    def test_register_actually_mints_on_every_one_of_the_105_registries(self) -> None:
        """Exercise :meth:`register` for real -- not just ``callable()`` --
        on every one of tier 1's 105 registries, the full set the shared
        template now reaches (:data:`ALL_105_REGISTRIES`), not only the 22
        with a bounded-unassigned range. A high, fixed value is deliberately
        outside any registry's assigned codes -- most bound themselves to 16
        bits or fewer -- so this cannot collide with anything either the CSV
        seeded or a sibling test minted.

        """
        value = 0x6E7A0001  # arbitrary, outside every registry's own domain
        name = 'PyPCAPKit_775_sweep'

        for module_name, class_name in ALL_105_REGISTRIES:
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)
                self.addCleanup(_purge_member, cls, name, value)

                before = len(cls.__members__)
                new = cls.register(value, name)
                after = len(cls.__members__)

                self.assertEqual(after, before + 1)
                self.assertIs(cls(value), new)
                self.assertIn(value, cls._value2member_map_)  # type: ignore[attr-defined]


class UnregisteredMemberHelperTests(unittest.TestCase):
    """:meth:`_unregistered_member` in isolation, on every one of the 105
    registries -- not only the 22 whose own ``_missing_`` happens to call it.
    It is part of the shared template regardless, so every registry carries
    it whether or not its own ``_missing_`` uses it yet (the other 83 keep
    their own bespoke ``process()``-driven ``_missing_``, out of tier 1's
    scope), and this pins that the helper itself behaves identically on all
    of them.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_builds_an_absent_member_on_every_registry(self) -> None:
        value = 0x6E7A0002  # arbitrary, distinct from the register() sweep's
        name = 'PyPCAPKit_775_unregistered'

        for module_name, class_name in ALL_105_REGISTRIES:
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)

                before = len(cls.__members__)
                member = cls._unregistered_member(value, name)  # type: ignore[attr-defined]
                after = len(cls.__members__)

                self.assertIsInstance(member, cls)
                self.assertEqual(member.value, value)
                self.assertEqual(member.name, name)
                self.assertEqual(before, after)
                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]
                self.assertNotIn(name, cls.__members__)


def _combining_operands(expr: 'ast.expr') -> 'Optional[list[ast.expr]]':
    """Every sub-expression ``expr`` *combines* with other, fixed text to
    build a new string, for the five shapes this tree's ``name`` arguments
    are ever manufactured from: ``%``-formatting, string concatenation, an
    f-string, ``str.format``, and ``sep.join([...])``. :obj:`None` if
    ``expr`` is not one of those five combining shapes *at its own top
    level* -- callers that want to see through a wrapping call
    (``.upper()``, ``str(...)``) around one of these do that separately;
    this function only recognises the combination itself.

    """
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        rhs = expr.right
        return list(rhs.elts) if isinstance(rhs, ast.Tuple) else [rhs]
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return [expr.left, expr.right]
    if isinstance(expr, ast.JoinedStr):
        # Both the interpolated value and its format spec can carry a
        # combined operand -- ``f'x_{y:{value}}'`` embeds ``value`` in
        # ``y``'s format spec, not in ``y`` itself.
        operands = []  # type: list[ast.expr]
        for part in expr.values:
            if isinstance(part, ast.FormattedValue):
                operands.append(part.value)
                if part.format_spec is not None:
                    operands.append(part.format_spec)
        return operands
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr == 'format':
            return list(expr.args) + [keyword.value for keyword in expr.keywords]
        if (expr.func.attr == 'join' and expr.args
                and isinstance(expr.args[0], (ast.List, ast.Tuple))):
            # ``sep.join([...])`` combines every element of the list/tuple
            # it is given -- ``sep`` itself (``expr.func.value``) is not an
            # operand in the same sense (it is the glue, not a part being
            # glued), so it is deliberately not included here.
            return list(expr.args[0].elts)
    return None


#: The conventional parameter names, across every ``_missing_``/``get()`` in
#: :mod:`pcapkit.const`, for the datum being looked up -- the one thing a
#: manufactured label must never be built *from*, since that is exactly what
#: risks an unbounded ``__members__`` collision. Anything else a combined
#: operand might reference (a namespace prefix, a fixed default, ...) is
#: provably not the value and is left alone.
_VALUE_PARAMETER_NAMES = frozenset({'value', 'key'})


def is_manufactured(name_arg: 'Optional[ast.expr]') -> 'bool':
    """Whether an ``_unregistered_member(...)`` call's ``name`` argument is
    built *from the value being looked up*, rather than being independent of
    it -- the one shape #775/#860's ruling forbids, because a label that
    varies with the value risks the exact ``__members__`` collision minting
    used to risk. Keyed on *which operand is combined*, not on the format
    spec: ``'%s_unknown' % namespace`` on :class:`~pcapkit.const.pcapng.
    option_type.OptionType`'s ``get()`` is a ``%``-format and is not
    flagged, because the combined operand is ``namespace`` (one of a
    handful of known prefixes) and not the value. ``'%s_unknown' % value``
    would be exactly the same shape and *would* be flagged, because there
    the combined operand is the value itself -- checking the format spec
    alone (e.g. "only ``%d`` is dangerous") would have missed that, and
    missed the identical risk written as ``'x_' + str(value)``,
    ``'x_{}'.format(value)`` or an f-string.

    ``sep.join([...])`` is a fifth combining shape in its own right --
    :func:`_combining_operands` treats every element of the list/tuple
    ``.join()`` is given as something combined, the same as a ``%``
    operand -- and recurses through any *other* wrapping call --
    ``('x_%s' % value).upper()``, ``str('x_%s' % value)``, ``f'x_{value}'.
    upper()`` -- rather than stopping at the outermost node: a
    ``.upper()``/``.zfill()``/``str(...)`` call around a combining shape
    does not undo the combination underneath it, so the receiver and every
    argument of *any* call are checked in turn. A bare
    reference to the value alone (``value``, ``value.upper()``,
    ``value.upper().zfill(4)``) is different in kind and is not flagged --
    nothing is combined with anything else there, which is exactly why the
    open-vocabulary registries (:class:`~pcapkit.const.ftp.command.
    FEATCode`/:class:`~pcapkit.const.ftp.command.Command`/
    :class:`~pcapkit.const.http.method.Method`) may use the value itself,
    case-folded, as the name: the ruling's target is a *manufactured*
    label, and folding case manufactures nothing.

    A bare string constant carries nothing substituted into it at all, so
    it is never flagged regardless of what characters it happens to
    contain. An :class:`~ast.IfExp` choosing between two safe branches, and
    a ``super()`` forward of the caller's own already-checked ``name``, are
    likewise left alone by recursing into their own sub-expressions rather
    than being hardcoded exemptions -- so a combining shape hidden inside
    either would still be caught.

    Round 5's review found that a call's *arguments* need a plainer rule
    than its receiver does: a bare ``value``/``key`` passed as data to
    ``str(...)``, ``operator.mod(...)``, ``.format_map(...)``, or nested
    inside a set/generator/list-comprehension/``map(...)`` argument to
    ``.join(...)``, is a reference this function used to clear the same
    way it clears a receiver -- wrongly, since an argument being the value
    at all is already how each of those shapes glues it to something
    else. Every argument of any call is therefore walked bluntly for
    ``value``/``key`` regardless of how deeply it is wrapped, while a
    receiver keeps the narrower, recursive check that preserves
    ``value.upper()``'s exemption.

    Known latent gap, deliberately not closed here: ``'x_%s' %
    self._value_`` (or ``cls._value_``) refers to the same datum through
    the enum machinery's own attribute rather than through the
    conventional ``value``/``key`` parameter name, which this function has
    no way to recognise without hardcoding attribute names as well as
    parameter names -- a broader heuristic than round 5 asked for. Nothing
    under :mod:`pcapkit.const` writes a ``name`` argument this way today.

    """
    if name_arg is None:
        return True
    if isinstance(name_arg, ast.Constant):
        return False
    if isinstance(name_arg, ast.Name):
        return False

    combined = _combining_operands(name_arg)
    if combined is not None:
        return any(
            isinstance(node, ast.Name) and node.id in _VALUE_PARAMETER_NAMES
            for operand in combined
            for node in ast.walk(operand)
        )

    if isinstance(name_arg, ast.Call):
        # The receiver of a method call (``<receiver>.upper()``) is
        # checked recursively, the same as the top-level expression would
        # be: a bare reference to the value alone stays exempt there (that
        # is the open-vocabulary case), while a combining shape hiding
        # behind it (``('x_%s' % value).upper()``) is still caught by
        # recursing into ``_combining_operands`` again.
        if isinstance(name_arg.func, ast.Attribute) and is_manufactured(name_arg.func.value):
            return True
        # Every argument, by contrast, is walked *bluntly* for a value/key
        # reference anywhere inside it, however deeply wrapped (a set,
        # generator or list comprehension, ``map(...)``, a further call,
        # ...) -- deliberately blunt, not because an argument can never be
        # an innocent reference, but because the failure direction is the
        # safe one (a false positive is loud and gets a fixture; a false
        # negative ships quietly), and no real call site under
        # ``pcapkit/const``/``pcapkit/vendor`` is affected either way
        # (measured: the sweep stays at 1012/0). It genuinely does over-flag:
        # ``value.upper()`` alone is exempt (it is the receiver case just
        # above), but the exact same expression as an *argument* --
        # ``str(value.upper())``, ``helper(value.upper())`` -- flags, so
        # wrapping an already-exempt transform in one more call changes the
        # verdict. ``NAMES.get(value, 'unknown')`` flags while the
        # semantically identical ``NAMES[value]`` does not, because one is
        # an ``ast.Call`` and the other an ``ast.Subscript`` -- this walk
        # only triggers on the former. A comprehension's loop variable or a
        # ``lambda``'s parameter that merely happens to be *spelled*
        # ``value``/``key`` also flags even when it is bound to something
        # entirely unrelated (``map(lambda value: value, namespace)``), since
        # nothing here tracks binding, only spelling. A keyword *name* that
        # happens to be ``value`` (``helper(value=namespace)``) does not
        # flag -- only the keyword's *own* value expression is walked, never
        # its argument name. If this fires on a real, innocent site: check
        # that the substituted operand truly is independent of the
        # looked-up datum, then add that site to the negative fixtures --
        # do not loosen this walk to make one site pass, since the whole
        # point of blunt-on-arguments is to keep it that way.
        for argument in list(name_arg.args) + [keyword.value for keyword in name_arg.keywords]:
            for node in ast.walk(argument):
                if isinstance(node, ast.Name) and node.id in _VALUE_PARAMETER_NAMES:
                    return True
        return False

    # Anything else -- an IfExp's test/body/orelse, a container literal
    # such as the list argument to ``.join([...])``, ... -- recurse into
    # its immediate children rather than giving up, since a combining
    # shape may be nested inside without the wrapper itself being one of
    # the shapes handled above.
    return any(is_manufactured(child) for child in ast.iter_child_nodes(name_arg))


#: Fixtures for :func:`is_manufactured`'s own self-check, run before it is
#: pointed at the real tree -- same discipline as :mod:`tests.const.
#: test_const_enum_builtin_parity`'s ``REPR_PERCENT_WALK_FIXTURES``: a
#: detector not shown to fire on a positive on purpose, and to stay quiet on
#: a negative, is not trustworthy on real code either. ``(label, source,
#: expected)`` where ``source`` is a full ``return cls._unregistered_member(
#: value, <name-expr>)`` statement parsed for its own ``name`` argument.
IS_MANUFACTURED_FIXTURES = (
    # The four manufactured shapes the round-2 review named explicitly --
    # each embeds ``value``, the thing being looked up, into the label.
    ('percent-s-value', "cls._unregistered_member(value, 'x_%s' % value)", True),
    ('percent-x-value', "cls._unregistered_member(value, 'x_%x' % value)", True),
    ('concat-str-value', "cls._unregistered_member(value, 'x_' + str(value))", True),
    ('format-method-value', "cls._unregistered_member(value, 'x_{}'.format(value))", True),
    # An f-string embedding value is the same shape as the four above.
    ('fstring-value', "cls._unregistered_member(value, f'x_{value}')", True),
    # Round-3 review's gap: a wrapping call around a combining shape --
    # hoisting a .upper()/.zfill()/str()/.join() outside the %/+/f-string
    # must not silently disable the guard.
    ('percent-value-then-upper', "cls._unregistered_member(value, ('x_%s' % value).upper())", True),
    ('percent-value-then-zfill', "cls._unregistered_member(value, ('x_%d' % value).zfill(8))", True),
    ('str-wrapping-percent', "cls._unregistered_member(value, str('x_%s' % value))", True),
    ('fstring-then-upper', "cls._unregistered_member(value, f'x_{value}'.upper())", True),
    ('join-list-with-value', "cls._unregistered_member(value, ''.join(['x_', str(value)]))", True),
    # Round-5 review's gap: on the generic call-recursion path, a bare
    # ``ast.Name`` argument (as opposed to the outermost expression) was
    # treated as exempt the same way ``value`` alone is at the top level --
    # which missed the value being glued in as *data* to a call rather than
    # merely transformed. None of these nine exists under pcapkit/const/
    # today (latent, not live), but the census that found them is exactly
    # what this fixture set exists to keep honest.
    ('join-set-with-value', "cls._unregistered_member(value, ''.join({'x_', str(value)}))", True),
    ('join-genexp-with-value',
     "cls._unregistered_member(value, ''.join(str(v) for v in [value]))", True),
    ('join-listcomp-with-value',
     "cls._unregistered_member(value, ''.join([str(v) for v in [value]]))", True),
    ('join-map-with-value',
     "cls._unregistered_member(value, ''.join(map(str, ['x_', value])))", True),
    ('dunder-mod-value', "cls._unregistered_member(value, 'x_%s'.__mod__(value))", True),
    ('operator-mod-value',
     "cls._unregistered_member(value, operator.mod('x_%s', value))", True),
    ('functools-reduce-value',
     "cls._unregistered_member(value, functools.reduce(operator.add, ['x_', str(value)]))", True),
    ('format-map-value',
     "cls._unregistered_member(value, 'x_{v}'.format_map({'v': value}))", True),
    ('fstring-format-spec-value',
     "cls._unregistered_member(value, f'x_{y:{value}}')", True),
    # The one real exemption: substitutes a bounded, non-value operand.
    ('percent-s-namespace', "cls._unregistered_member(key, '%s_unknown' % namespace)", False),
    # Every other real call site in the tree: nothing substituted at all.
    ('bare-literal', "cls._unregistered_member(value, 'Unassigned')", False),
    ('bare-name', "cls._unregistered_member(value, name)", False),
    ('upper-call', "cls._unregistered_member(value, value.upper())", False),
    ('upper-zfill-chain', "cls._unregistered_member(value, value.upper().zfill(4))", False),
    ('ifexp-names', "cls._unregistered_member(value, default if default is not None else name)", False),
    ('super-forward', "super()._unregistered_member(value, name)", False),
)


class IsManufacturedSelfCheckTests(unittest.TestCase):
    """:func:`is_manufactured` against its own fixtures, before it is
    trusted against the real tree below."""

    def test_self_check(self) -> None:
        for label, source, expected in IS_MANUFACTURED_FIXTURES:
            with self.subTest(fixture=label):
                call = ast.parse(source, mode='eval').body
                assert isinstance(call, ast.Call)
                name_arg = call.args[1]
                self.assertEqual(is_manufactured(name_arg), expected,
                                 f'{label}: {source!r}')


#: The one call-chain every hex-suffixed manufactured name shares, on all 53
#: branches #775's final round deliberately kept unrenamed rather than
#: converting to the bare placeholder every other converted registry uses
#: (``Xyplex_0x0888``, ``Registered by Xerox_0x0010``, ...; see that
#: sweep's own docstring, and the module docstring's closing paragraph, for
#: why keeping the hex suffix is safe despite being exactly the shape
#: :func:`is_manufactured` exists to flag elsewhere): ``hex(value)[2:]
#: .upper().zfill(4)``, the exact expression substituted into the ``%s`` of
#: each literal's own ``'..._0x%s'`` left operand. Parsed once, here, so a
#: real call site's own right operand can be compared against it
#: structurally (:func:`ast.dump`) rather than restated as a string or
#: source-text match, which would have to be re-derived per literal prefix
#: and would drift the moment whitespace in the generated source changes.
_HEX_SUFFIX_SHAPE = ast.parse('hex(value)[2:].upper().zfill(4)', mode='eval').body


def _is_hex_suffixed_unregistered_name(name_arg: 'Optional[ast.expr]') -> bool:
    """Whether ``name_arg`` is *exactly* the one shape #775's final round
    preserved unrenamed on :class:`~pcapkit.const.reg.ethertype.EtherType`'s
    52 range branches and :class:`~pcapkit.const.ipx.socket.Socket`'s one --
    a ``%``-format :class:`~ast.BinOp` whose left operand is a string
    constant ending in the literal ``'_0x%s'``, and whose right operand is
    structurally identical (by :func:`ast.dump`, so source-text formatting
    such as whitespace or quote style never matters) to
    :data:`_HEX_SUFFIX_SHAPE`.

    Deliberately narrower than :func:`is_manufactured`'s own
    combining-operand check: it exists only to pick these 53 already-
    manufactured calls -- the ones #775's ruling explicitly asked to keep
    exactly as rendered -- out from every *other* manufactured call
    :func:`is_manufactured` still (correctly) flags, not to re-decide what
    counts as manufactured in the first place. Matching on the ``name``
    argument's own shape, rather than on which file the call happens to
    live in, means this predicate by itself rejects a differently-shaped
    manufactured name wherever it appears. It does *not*, by itself,
    reject a correctly hex-suffixed name planted in some other,
    unintended file -- that half of the safety comes from the sweep's own
    ``assertEqual(exempt_hits, 53)`` below, not from this function, so the
    two are a pair and neither is trustworthy alone.

    """
    if not (isinstance(name_arg, ast.BinOp) and isinstance(name_arg.op, ast.Mod)):
        return False
    left, right = name_arg.left, name_arg.right
    if not (isinstance(left, ast.Constant) and isinstance(left.value, str)
            and left.value.endswith('_0x%s')):
        return False
    return ast.dump(right) == ast.dump(_HEX_SUFFIX_SHAPE)


class UnregisteredMemberNameIsBareTests(unittest.TestCase):
    """The naming rule settled under GitHub issue #775's tier 1: a non-minting
    pseudo-member carries the registry's own ``unassigned``/``reserved`` name
    bare, with no numeric value appended. Minted members keep their number,
    because there it is part of the real name (``Motorola_0x8705`` names one
    EtherType inside Motorola's block). Asked whether the non-minting path should
    honour the registry's own name directly or keep appending the numeric value,
    the owner chose the bare name -- safe precisely because a
    pseudo-member built by :meth:`_unregistered_member` never enters
    ``__members__``/``_member_map_``/``_value2member_map_``, so two same-named
    pseudo-members (e.g. ``Chunk._unregistered_member(20, 'Unassigned')`` and
    ``(70, 'Unassigned')``) cannot collide the way two *minted*
    ``extend_enum`` members with the same name would.

    This walks every generated :mod:`pcapkit.const` module by AST -- rather
    than pinning one example -- and asserts that every
    ``cls._unregistered_member(...)`` call site's ``name`` argument is not a
    *manufactured* numeric-suffixed label: a bare string constant containing
    ``%`` (the old ``'Unassigned_%d' % value`` shape, spelled out as a
    literal), or an equivalent ``%``-formatted :class:`~ast.BinOp` or
    f-string. It therefore covers all 49 call sites tier 1's follow-up
    touched, the 172 tier 2's #775/#847 ruling added, and -- since #860
    step 2's PR 1 -- the 15 more across :class:`~pcapkit.const.http.
    status_code.StatusCode`, :class:`~pcapkit.const.ftp.return_code.
    ReturnCode`, :class:`~pcapkit.const.ftp.return_code.ResponseKind`,
    :class:`~pcapkit.const.ftp.return_code.GroupingInformation`,
    :class:`~pcapkit.const.pcapng.option_type.OptionType`,
    :class:`~pcapkit.const.ftp.command.FEATCode`,
    :class:`~pcapkit.const.ftp.command.Command` and
    :class:`~pcapkit.const.http.method.Method` (see
    :data:`BESPOKE_UNMINT_CONVERTED_REGISTRIES` above), plus every
    ``super()._unregistered_member(value, name)`` forwarding call each of
    those five ``__new__``-carrying overrides makes internally -- not a
    fresh call site with a label of its own, just relaying whatever the true
    call site already passed, so it is walked and counted here too rather
    than specially excluded -- plus 2 more round 2 review found still
    minting on :class:`OptionType`'s own ``get()`` (its int/namespace path
    and its ``str`` path, both independent of ``_missing_``), for 244 total
    as of PR 1. PR 2 then added the 766 ``_missing_`` branches on
    :class:`~pcapkit.const.reg.apptype.apptype.AppType` itself, the one more
    inside its own ``get()``, and the one ``super()._unregistered_member(...)``
    forward its own override makes -- 768 more, for 1012 total; see
    :class:`AppTypeUnmintConvertedTests` below.
    ``'%s_unknown' % namespace`` on the first of those two is deliberately
    *not* flagged as manufactured despite being a ``%``-formatted
    :class:`~ast.BinOp`: unlike ``'Unassigned_%d' % value``, the substituted
    operand is a bounded namespace prefix, not the value being minted, so it
    carries none of the numeric-suffix collision risk the check exists to
    catch -- see :func:`is_manufactured`'s own docstring below.

    The last three of those fifteen are a genuinely different shape from
    every other converted registry: the ``name`` argument (the identifier
    each is looked up by, canonicalised to upper case for all three --
    matching how every *registered* member of :class:`Command`/
    :class:`Method`/:class:`FEATCode` is already looked up) is not a
    manufactured placeholder at all, it is the exact wire keyword itself,
    just upper-cased -- so the argument is a bare :class:`~ast.Name` or a
    plain (non-``%``) expression rather than a string constant. The
    ``value`` argument, by contrast, is deliberately *not* touched on any
    of the three: it stays exactly the caller's own casing, matching what
    :meth:`~pcapkit.const.ftp.command.Command._unregistered_member`'s own
    docstring documents as the shared convention (see
    :meth:`BespokeOpenVocabularyUnmintConvertedTests.
    test_command_missing_no_longer_mints` and its siblings). Neither
    argument is *formatted* with a numeric suffix on any of the three,
    which is the one thing that would risk a genuine ``__members__``
    collision if these were ever minted instead of built unregistered.

    A call site still using ``extend_enum(...)`` instead of
    ``_unregistered_member(...)`` at all -- :class:`~pcapkit.const.mh.
    cga_type.CGAType`, plus ``register``/``register_alias`` on every registry
    (including :class:`~pcapkit.const.reg.apptype.apptype.AppType`'s own,
    added by PR 2) -- is out of scope and untouched by this sweep entirely,
    since it never calls ``_unregistered_member`` in the first place; minting
    there is the explicit, caller-named path the sweep is not about.

    (Corrected from an earlier draft of this docstring, which estimated
    "~92 registries still mint" and named ``pcapkit.const.mh`` and
    ``BlockType`` as examples -- both were converted by tier 2 and no longer
    apply; the AST walk in the module docstring above measured the real
    figure at 89.)

    GitHub issue #775's final round converts the last 53 minting branches --
    all 52 of :class:`~pcapkit.const.reg.ethertype.EtherType`'s and
    :class:`~pcapkit.const.ipx.socket.Socket`'s one -- and deliberately keeps
    each one's hex-suffixed name unchanged (PR #878 scoped it this way:
    keeping the existing hex-suffixed name, since this change is about not
    registering rather than renaming). That is the exact manufactured,
    value-suffixed shape :func:`is_manufactured` exists to flag -- unlike
    ``'%s_unknown' % namespace`` above, the substituted operand here really is
    ``value``, via ``hex(value)[2:].upper().zfill(4)``. Flagging it anyway
    would be a false positive in the sense that matters: the collision this
    check protects against is two *minted* members sharing a name at different
    values, and neither of these 53 calls ever mints, so nothing can collide
    regardless of what the ``name`` argument looks like.
    :func:`_is_hex_suffixed_unregistered_name` below is the scoped fix -- an
    exemption keyed on the ``name`` argument's own AST shape, not on which
    file the call lives in, from the sweep only -- not a change to
    :func:`is_manufactured` itself, which stays exactly as tested against
    :data:`IS_MANUFACTURED_FIXTURES` and keeps flagging this shape everywhere
    else it might appear.

    """

    def test_every_unregistered_member_call_passes_a_non_manufactured_name(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        const_root = repo_root / 'pcapkit' / 'const'
        self.assertTrue(const_root.is_dir(), f'{const_root} is not a directory')

        offenders = []  # type: list[str]
        call_count = 0
        exempt_hits = 0

        for path in sorted(const_root.rglob('*.py')):
            source = path.read_text()
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not (isinstance(func, ast.Attribute) and func.attr == '_unregistered_member'):
                    continue

                call_count += 1
                args = node.args
                name_arg = args[1] if len(args) > 1 else None
                if is_manufactured(name_arg):
                    if _is_hex_suffixed_unregistered_name(name_arg):
                        exempt_hits += 1
                        continue
                    segment = ast.get_source_segment(source, node)
                    offenders.append(f'{path.relative_to(repo_root)}:{node.lineno}: {segment}')

        # Sanity: the sweep itself must actually be exercising something --
        # tier 1's follow-up touched exactly 49 call sites across 21 files,
        # tier 2's #775/#847 ruling added 172 more across 82 files, and
        # #860 step 2's PR 1 added 11 more (true call sites plus each
        # override's own ``super()`` forward, plus the 2 round-2 review found
        # still minting on OptionType.get()'s own two paths) across 2 files,
        # for 244 total. #860 step 2's PR 2 then added the 766 ``_missing_``
        # branches on AppType itself, the one more inside its own ``get()``,
        # and the one ``super()._unregistered_member(...)`` forward its own
        # override makes -- 768 more, in one file, for 1012 total. #775's
        # final round then added the 52 on EtherType and the 1 on Socket --
        # 53 more, for 1065 total measured on this tree.
        self.assertGreaterEqual(call_count, 1065,
                                 f'expected at least 1065 _unregistered_member call sites, found {call_count}')
        # And that the exemption is actually earning its keep, rather than a
        # dead carve-out nothing reaches any more: exactly 53, matching the
        # 52 EtherType range branches plus Socket's one.
        self.assertEqual(exempt_hits, 53,
                          f'expected exactly 53 hex-suffixed-name exemptions to fire, found {exempt_hits}')
        self.assertEqual(offenders, [],
                          'found _unregistered_member call(s) with a manufactured name:\n'
                          + '\n'.join(offenders))


class RulingConversionDoesNotMintTests(unittest.TestCase):
    """Tier 2's #775/#847 ruling, behaviourally: a value that used to mint a
    bare status word must now come back as a throwaway pseudo-member instead,
    the same regression :class:`UnassignedRangeDoesNotMintTests` above proves
    for tier 1's 21. Swept across :data:`RULING_CONVERTED_WITH_REACHABLE_GAP`
    -- the 69 of the 82 converted registries whose branch a real lookup can
    actually reach; the other 13 are proved by source instead, in
    :class:`RulingConversionSourceTests` below."""

    if TYPE_CHECKING:
        registries: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.registries = [
            getattr(importlib.import_module(module_name), class_name)
            for module_name, class_name in RULING_CONVERTED_WITH_REACHABLE_GAP
        ]
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_converted_value_does_not_mint(self) -> None:
        for cls in self.registries:
            with self.subTest(registry=cls.__qualname__):
                value = _first_unregistered_value(cls)
                self.assertIsNotNone(value, f'{cls.__qualname__} has no reachable converted branch')
                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]

                before = len(cls.__members__)
                member = cls(value)
                after = len(cls.__members__)

                self.assertEqual(member.value, value)
                self.assertEqual(before, after)
                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]
                self.assertNotIn(member.name, cls.__members__)

    def test_repeated_lookup_does_not_grow_members(self) -> None:
        for cls in self.registries:
            with self.subTest(registry=cls.__qualname__):
                value = _first_unregistered_value(cls)
                self.assertIsNotNone(value, f'{cls.__qualname__} has no reachable converted branch')
                before = len(cls.__members__)

                first = cls(value)
                after_one = len(cls.__members__)
                second = cls(value)
                after_two = len(cls.__members__)

                self.assertEqual(before, after_one)
                self.assertEqual(before, after_two)
                self.assertEqual(first, second)
                self.assertIsNot(first, second)


#: :class:`~pcapkit.const.reg.ethertype.EtherType` and :class:`~pcapkit.const.
#: ipx.socket.Socket` used to be the two *mixed* registries: most of their
#: ``_missing_`` legitimately kept minting (real attributed names), so the
#: blanket "no extend_enum left" sweep below did not apply to them.
#: GitHub issue #775's final round converts every remaining branch on both,
#: so neither is mixed any more -- kept as an empty-by-construction frozenset
#: (rather than deleted outright) so the two subtractions below stay
#: self-documenting about *why* nothing is excluded now, and so a future
#: registry that goes back to being genuinely mixed has a named place to be
#: added again. :class:`EtherTypeMixedMintTests` and
#: :class:`IPXSocketMixedMintTests` (retitled in place, not renamed) now prove
#: their formerly-kept probe no longer mints either, alongside the rows that
#: already didn't.
_MIXED_REGISTRIES = frozenset()  # type: frozenset[tuple[str, str]]


class RulingConversionSourceTests(unittest.TestCase):
    """Source-level proof for the 13 of :data:`RULING_CONVERTED_REGISTRIES`
    with no reachable gap (every in-bounds value already names a real member,
    so no lookup can exercise the branch either before or after this change)
    -- and, as a completeness check, for the 80 wholly-converted registries:
    none of their ``_missing_`` bodies may call :func:`~aenum.extend_enum`
    any more. :data:`_MIXED_REGISTRIES` is empty as of #775's final round, so
    nothing is excluded here any more -- see its own docstring."""

    def test_no_reachable_gap_registries_no_longer_call_extend_enum(self) -> None:
        # EtherType now belongs to RULING_CONVERTED_WITH_REACHABLE_GAP: its
        # masked-branch exclusion (Old Xerox shadowed by the wider IEEE802.3
        # range) was fixed under GitHub issue #862, and its first converted
        # branch by source order is directly probeable like any other
        # reachable-gap registry now. The `_MIXED_REGISTRIES` subtraction
        # below is a defensive no-op today -- neither mixed registry needs
        # removing from `RCR - RG` any more (EtherType is already in RG;
        # Socket never appeared in RULING_CONVERTED_REGISTRIES to begin with)
        # -- kept so a mixed registry that regains a masked or absent branch
        # in the future does not silently inflate this count.
        excluded = set(RULING_CONVERTED_REGISTRIES) - set(RULING_CONVERTED_WITH_REACHABLE_GAP) - _MIXED_REGISTRIES
        self.assertEqual(len(excluded), 13, 'expected exactly 13 registries with no reachable gap')
        for module_name, class_name in sorted(excluded):
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)
                source = inspect.getsource(cls._missing_)  # type: ignore[attr-defined]
                self.assertNotIn('extend_enum', source)
                self.assertIn('_unregistered_member', source)

    def test_every_wholly_converted_registry_no_longer_calls_extend_enum(self) -> None:
        for module_name, class_name in RULING_CONVERTED_REGISTRIES:
            if (module_name, class_name) in _MIXED_REGISTRIES:
                continue
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)
                source = inspect.getsource(cls._missing_)  # type: ignore[attr-defined]
                self.assertNotIn('extend_enum', source)

    def test_ethertype_and_socket_no_longer_call_extend_enum_either(self) -> None:
        """The two former mixed registries, now that nothing excludes them:
        GitHub issue #775's final round leaves no ``extend_enum`` call on
        either, the same invariant :meth:`test_every_wholly_converted_
        registry_no_longer_calls_extend_enum` already proves for the other
        80 -- named separately because neither is actually a member of
        :data:`RULING_CONVERTED_REGISTRIES` in Socket's case, so the loop
        above alone would never reach it."""
        from pcapkit.const.ipx.socket import Socket
        from pcapkit.const.reg.ethertype import EtherType

        for cls in (EtherType, Socket):
            with self.subTest(registry=cls.__qualname__):
                source = inspect.getsource(cls._missing_)  # type: ignore[attr-defined]
                self.assertNotIn('extend_enum', source)
                self.assertIn('_unregistered_member', source)


class EtherTypeMixedMintTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.ethertype.EtherType` was the ruling's mixed
    case: ``DEC Unassigned`` and the "Old Xerox Experimental..." row converted
    first, while every other attributed vendor block (a real company's own
    name for its own code) kept minting. GitHub issue #775's final round
    converts the rest too -- :meth:`test_formerly_attributed_vendor_block_
    no_longer_mints` below proves the one named probe (``Xyplex``) that used
    to be this class's own regression guard for "still mints" now proves the
    opposite, and the class is no longer actually mixed (retitled in place
    rather than renamed, so history stays easy to follow)."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_unassigned_rows_do_not_mint(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        for value, name in ETHERTYPE_UNASSIGNED_PROBES.items():
            with self.subTest(value=hex(value)):
                self.assertNotIn(value, EtherType._value2member_map_)  # type: ignore[attr-defined]
                before = len(EtherType.__members__)

                member = EtherType(value)

                self.assertEqual(member.value, value)
                self.assertEqual(member.name, name)
                self.assertEqual(before, len(EtherType.__members__))
                self.assertNotIn(value, EtherType._value2member_map_)  # type: ignore[attr-defined]

    # ``test_masked_old_xerox_row_converts_by_source`` retired here, not simply
    # deleted: it used to prove 0x0101-0x01FF converts *by source* (an
    # order-insensitive string search for the two calls in
    # EtherType._missing_'s text) because the row was unreachable at runtime,
    # masked by the wider 0x0000-0x05DC branch that preceded it. GitHub issue
    # #862, fixed by #865, reordered the generator so that row is no longer
    # masked, and 0x0101 is now one of the values ``test_unassigned_rows_do_
    # not_mint`` above probes directly via ``ETHERTYPE_UNASSIGNED_PROBES`` --
    # a strictly stronger, behavioural proof of the same fact (it also catches
    # a regression the old source check would have missed: the string search
    # never checked *order*, so it would keep passing even if the ordering
    # regressed and 0x0101 started minting again). Nothing this test checked
    # is left unchecked; it is subsumed rather than replaced by a weaker test.

    def test_formerly_attributed_vendor_block_no_longer_mints(self) -> None:
        """The regression guard this class used to carry the other way: this
        exact probe (``Xyplex``, 0x0888) used to prove the ruling *kept*
        minting a real attributed name; GitHub issue #775's final round
        converts it, preserving the hex-suffixed name exactly as the crawler
        always rendered it -- PR #878 scoped it this way: keeping the existing
        hex-suffixed name, since this change is about not registering rather
        than renaming. Same shape as :meth:`test_unassigned_rows_do_not_mint`
        above, just for the one probe that used to be the exception."""
        from pcapkit.const.reg.ethertype import EtherType

        value, name = ETHERTYPE_FORMERLY_KEPT_PROBE
        self.assertNotIn(value, EtherType._value2member_map_)  # type: ignore[attr-defined]
        before = len(EtherType.__members__)

        member = EtherType(value)

        self.assertEqual(member.value, value)
        self.assertEqual(member.name, name)
        self.assertEqual(before, len(EtherType.__members__))
        self.assertNotIn(value, EtherType._value2member_map_)  # type: ignore[attr-defined]

        second = EtherType(value)
        self.assertEqual(member, second)
        self.assertIsNot(member, second)


class IPXSocketMixedMintTests(unittest.TestCase):
    """:class:`~pcapkit.const.ipx.socket.Socket` was the ruling's other mixed
    case: ``Experimental`` and the three dynamically/statically assigned
    labels converted first, while ``Registered by Xerox``, the company one,
    kept minting. GitHub issue #775's final round converts it too; see
    :meth:`test_registered_by_xerox_no_longer_mints` below."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_unassigned_rows_do_not_mint(self) -> None:
        from pcapkit.const.ipx.socket import Socket

        for value, name in IPX_SOCKET_UNASSIGNED_PROBES.items():
            with self.subTest(value=hex(value)):
                self.assertNotIn(value, Socket._value2member_map_)  # type: ignore[attr-defined]
                before = len(Socket.__members__)

                member = Socket(value)

                self.assertEqual(member.value, value)
                self.assertEqual(member.name, name)
                self.assertEqual(before, len(Socket.__members__))
                self.assertNotIn(value, Socket._value2member_map_)  # type: ignore[attr-defined]

    def test_registered_by_xerox_no_longer_mints(self) -> None:
        """The regression guard this class used to carry the other way: this
        exact probe (``Registered by Xerox``, 0x0010) used to prove the
        ruling *kept* minting the company name; GitHub issue #775's final
        round converts it, preserving the hex-suffixed name exactly as the
        crawler always rendered it -- same ruling, same reasoning as
        :meth:`EtherTypeMixedMintTests.
        test_formerly_attributed_vendor_block_no_longer_mints`."""
        from pcapkit.const.ipx.socket import Socket

        value, name = IPX_SOCKET_FORMERLY_KEPT_PROBE
        self.assertNotIn(value, Socket._value2member_map_)  # type: ignore[attr-defined]
        before = len(Socket.__members__)

        member = Socket(value)

        self.assertEqual(member.value, value)
        self.assertEqual(member.name, name)
        self.assertEqual(before, len(Socket.__members__))
        self.assertNotIn(value, Socket._value2member_map_)  # type: ignore[attr-defined]

        second = Socket(value)
        self.assertEqual(member, second)
        self.assertIsNot(member, second)


#: The 5 (of #860's original 9 bespoke) classes step 2's PR 1 brought onto
#: :class:`~pcapkit.corekit.enum.EnumRegistry` and converted: (module, class
#: name, a probe value inside the converted range, the bare label the
#: conversion uses). Every one of these five has a custom ``__new__`` with
#: extra per-member attributes, unlike any of the 82 tier-2 registries in
#: :data:`RULING_CONVERTED_REGISTRIES` above, which is exactly why each needed
#: its own ``_unregistered_member`` override rather than the shared generic
#: one -- see :class:`BespokeUnmintConvertedRegistriesTests`.
BESPOKE_UNMINT_CONVERTED_REGISTRIES = (
    ('pcapkit.const.http.status_code', 'StatusCode', 105, 'Unassigned'),
    ('pcapkit.const.ftp.return_code', 'ReturnCode', 199, 'Unassigned'),
    ('pcapkit.const.ftp.return_code', 'ResponseKind', 9, 'Unknown'),
    ('pcapkit.const.ftp.return_code', 'GroupingInformation', 9, 'Unknown'),
    ('pcapkit.const.pcapng.option_type', 'OptionType', 65000, 'opt_unknown'),
)


class BespokeUnmintConvertedRegistriesTests(unittest.TestCase):
    """GitHub issue #860 step 2, PR 1: 5 of the 9 bespoke, non-
    :class:`~pcapkit.corekit.enum.EnumRegistry` classes brought onto the base
    and converted. Unlike every registry above, each of these five carries a
    custom ``__new__`` setting extra attributes (``message``;
    ``description``/``kind``/``group``; ``opt_name``/``opt_value``), so the
    base's generic :meth:`~pcapkit.corekit.enum.EnumRegistry.
    _unregistered_member` -- which calls the member type's ``__new__``
    directly and sets only ``_name_``/``_value_`` -- would leave those
    attributes unset and make ``str()``/``repr()`` raise on the result. Each
    class therefore overrides :meth:`_unregistered_member` to reconstruct
    them the same way ``__new__`` would. These tests exercise that
    reconstruction directly, not just that lookup no longer mints.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_unassigned_value_resolves_without_minting(self) -> None:
        """Swept across all 5: resolves, does not mint, repeated lookup is
        equal but not identical -- the same shape as
        :class:`UnassignedRangeDoesNotMintTests` above, generalised to
        registries whose ``_unregistered_member`` is not the generic one."""
        for module_name, class_name, value, label in BESPOKE_UNMINT_CONVERTED_REGISTRIES:
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)

                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]
                before = len(cls.__members__)

                first = cls(value)
                after_one = len(cls.__members__)
                second = cls(value)
                after_two = len(cls.__members__)

                self.assertEqual(before, after_one)
                self.assertEqual(before, after_two)
                self.assertEqual(first, second)
                self.assertIsNot(first, second)
                self.assertEqual(first.name, label)
                self.assertNotIn(value, cls._value2member_map_)  # type: ignore[attr-defined]
                self.assertNotIn(label, cls.__members__)

    def test_out_of_bound_value_still_fails(self) -> None:
        for module_name, class_name, _, _label in BESPOKE_UNMINT_CONVERTED_REGISTRIES:
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)
                with self.assertRaises(ValueError):
                    cls(1 << 32)

    def test_statuscode_unregistered_member_displays_correctly(self) -> None:
        """Pins that :attr:`message` -- set only by ``__new__`` on the base
        template -- is reconstructed, since :meth:`__str__` reads it and
        would raise :exc:`AttributeError` on a member built the generic way."""
        from pcapkit.const.http.status_code import StatusCode

        member = StatusCode(105)
        self.assertEqual(member.message, 'Unassigned')
        self.assertEqual(repr(member), '<StatusCode [105]>')
        self.assertEqual(str(member), '[105] Unassigned')

    def test_statuscode_every_unassigned_range_resolves_without_minting(self) -> None:
        """All 8 of :meth:`~pcapkit.const.http.status_code.StatusCode.
        _missing_`'s ``if`` branches, not just the first -- each is its own
        source line and its own converted call, so covering only one leaves
        seven untested."""
        from pcapkit.const.http.status_code import StatusCode

        for value in (105, 209, 227, 309, 419, 432, 452, 512):
            with self.subTest(value=value):
                before = len(StatusCode.__members__)
                member = StatusCode(value)
                self.assertEqual(len(StatusCode.__members__), before)
                self.assertEqual(member.message, 'Unassigned')
                self.assertEqual(member.value, value)
                self.assertNotIn(value, StatusCode._value2member_map_)  # type: ignore[attr-defined]

    def test_returncode_unregistered_member_displays_correctly(self) -> None:
        """Pins that :attr:`description`, :attr:`kind` and :attr:`group` are
        all reconstructed -- :attr:`kind`/:attr:`group` are themselves derived
        by looking the two code digits up on :class:`ResponseKind` and
        :class:`GroupingInformation`, which must resolve (through their own
        conversion above) without minting either."""
        from pcapkit.const.ftp.return_code import (GroupingInformation, ReturnCode,
                                                    ResponseKind)

        rk_before = len(ResponseKind.__members__)
        gi_before = len(GroupingInformation.__members__)

        member = ReturnCode(199)
        self.assertIsNone(member.description)
        self.assertIsInstance(member.kind, ResponseKind)
        self.assertEqual(member.kind, 1)
        self.assertIsInstance(member.group, GroupingInformation)
        self.assertEqual(member.group, 9)
        self.assertEqual(repr(member), '<ReturnCode [199]>')
        self.assertEqual(str(member), '[199] None')

        # The nested ResponseKind(1)/GroupingInformation(9) resolutions must
        # not mint on either sub-registry either -- 1 is a real ResponseKind
        # member (PositivePreliminary) so it resolves directly, but 9 is
        # itself in GroupingInformation's own unassigned range and must go
        # through *its* conversion above rather than minting.
        self.assertEqual(gi_before, len(GroupingInformation.__members__))
        self.assertEqual(rk_before, len(ResponseKind.__members__))

    def test_responsekind_and_groupinginformation_unregistered_member_bare_name(self) -> None:
        """Neither has a custom ``__new__``, so the base's generic
        ``_unregistered_member`` needs no override for either -- pinned here
        so a future edit that adds one notices it changed something that
        used to be free."""
        from pcapkit.const.ftp.return_code import GroupingInformation, ResponseKind

        self.assertNotIn('_unregistered_member', ResponseKind.__dict__)
        self.assertNotIn('_unregistered_member', GroupingInformation.__dict__)

        rk = ResponseKind(9)
        self.assertEqual(rk.name, 'Unknown')
        gi = GroupingInformation(9)
        self.assertEqual(gi.name, 'Unknown')

    def test_optiontype_unregistered_member_displays_correctly(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        member = OptionType(65000)
        self.assertEqual(member.opt_name, 'opt_unknown')
        self.assertEqual(member.opt_value, 65000)
        self.assertEqual(repr(member), '<OptionType.opt_unknown: 65000>')
        self.assertEqual(str(member), 'opt_unknown [65000]')

    def test_optiontype_members_ns_is_not_corrupted(self) -> None:
        """The maintainer's own second lookup table, :attr:`__members_ns__`,
        sits alongside ``_value2member_map_`` and must not grow from an
        unregistered lookup either -- growing it would silently defeat the
        whole point of *unregistered* through a side channel the generic
        ``_value2member_map_``/``__members__`` assertions above cannot see.
        This is deliberately the opposite of what the pre-conversion mint did
        (it *did* add to ``__members_ns__``, every time), so it is pinned
        both ways: the table must not grow, and the value must not appear in
        it, either directly under the resolving namespace."""
        from pcapkit.const.pcapng.option_type import OptionType

        before = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        first = OptionType(65000)
        second = OptionType(65000)

        after = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}
        self.assertEqual(before, after)
        for members in OptionType.__members_ns__.values():
            self.assertNotIn(65000, members)
        # And, since it never entered the table, two lookups build two
        # independent (equal, non-identical) objects rather than the single
        # cached one a real namespace entry would have returned.
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_optiontype_get_int_path_no_longer_mints(self) -> None:
        """:meth:`OptionType.get` used to mint directly on a miss (bypassing
        ``_missing_`` entirely) -- a second, independent mint site this PR's
        first pass left alone. Round 2 review measured it live on the
        wire-facing path (:meth:`pcapkit.protocols.misc.pcapng.PCAPNG.
        _make_pcapng_options` calls ``get()`` with raw option-code bytes),
        and the owner's ruling names ``get`` explicitly -- the same reason
        :class:`~pcapkit.const.ftp.command.Command`/:class:`~pcapkit.const.
        http.method.Method`'s own ``get()`` mint sites converted. Leaving
        this one minting while ``_missing_`` did not would have been the
        exact contradiction that conversion was for."""
        from pcapkit.const.pcapng.option_type import OptionType

        before = len(OptionType.__members__)
        ns_before = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        first = OptionType.get(65001)
        after = len(OptionType.__members__)
        ns_after = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        self.assertEqual(after, before)
        self.assertEqual(ns_before, ns_after)
        self.assertNotIn(65001, OptionType.__members_ns__.get('opt', {}))

        second = OptionType.get(65001)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_optiontype_get_namespace_path_no_longer_mints(self) -> None:
        """The same call, through a non-default ``namespace=`` -- a
        different branch of the same ``if isinstance(key, int)`` block."""
        from pcapkit.const.pcapng.option_type import OptionType

        before = len(OptionType.__members__)
        ns_before = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        first = OptionType.get(65002, namespace='if')
        after = len(OptionType.__members__)
        ns_after = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        self.assertEqual(after, before)
        self.assertEqual(ns_before, ns_after)
        self.assertNotIn(65002, OptionType.__members_ns__.get('if', {}))
        self.assertEqual(first.opt_name, 'if_unknown')

        second = OptionType.get(65002, namespace='if')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_optiontype_get_str_path_no_longer_mints(self) -> None:
        """The subtler of the two: ``get()``'s ``str``-keyed branch used to
        mint ``key`` itself as the member's *name*, with ``default`` as its
        value -- the same "no information to register one properly"
        reasoning as the int path, just with the roles of ``key`` and
        ``default`` swapped in the old ``extend_enum`` call."""
        from pcapkit.const.pcapng.option_type import OptionType

        before = len(OptionType.__members__)
        ns_before = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        first = OptionType.get('pypcapkit_860_probe', 42)
        after = len(OptionType.__members__)
        ns_after = {ns: dict(members) for ns, members in OptionType.__members_ns__.items()}

        self.assertEqual(after, before)
        self.assertEqual(ns_before, ns_after)
        self.assertNotIn('pypcapkit_860_probe', OptionType.__members__)
        self.assertEqual(first.opt_name, 'pypcapkit_860_probe')
        self.assertEqual(first.opt_value, 42)

        second = OptionType.get('pypcapkit_860_probe', 42)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class BespokeOpenVocabularyUnmintConvertedTests(unittest.TestCase):
    """The 3 open-vocabulary ``StrEnum`` classes -- unlike every other unmint
    branch converted above or on tier 2, none of these three minted a
    synthetic numeric placeholder under a procedural label
    (``Unassigned_%d``, ``Unknown_%d``); each minted the literal, exact
    string it was asked to resolve, as its own name. That initially read as
    a case for keeping them minting (the label was never manufactured), but
    GitHub issue #860 settled it the other way: ``get()`` does not mint,
    because only ``register()`` creates a new registry entry, and for these
    registries only IANA-registered values are legitimate -- ``get()``
    simply does not have enough information to build a new one. Concretely:
    :class:`~pcapkit.const.ftp.command.Command` needs ``feat``/``desc``/``type``/``conf`` and
    :class:`~pcapkit.const.http.method.Method` needs
    ``safe``/``idempotent``, neither of which a bare wire string carries, so
    minting used to register a permanently hollowed-out member for each.
    :class:`~pcapkit.const.ftp.command.FEATCode` has no custom ``__new__``
    at all and needed no override.

    Both ``_missing_`` and each class's own ``get()`` (a *second*,
    independent mint site bypassing ``_missing_`` entirely, the same shape
    as :class:`~pcapkit.const.pcapng.option_type.OptionType`'s) are
    converted, since the owner's reasoning names ``get`` explicitly and
    leaving it minting while ``_missing_`` did not would have been a
    direct contradiction. ``Command``/``Method``'s ``_unregistered_member``
    override canonicalises the constructed value to the same upper-case
    ``name`` used for the lookup (rather than the caller's incidental input
    casing), which is also what makes ``get('frob')`` and ``get('FROB')``
    compare *equal* even though, with nothing cached any more, they can
    never again be *identical* -- see the two production regression tests
    this forced: ``tests/protocols/application/test_ftp_unit.py::
    FTPTestCase::test_command_get_is_case_insensitive`` and
    ``tests/protocols/application/test_http_unit.py::HTTPTestCase::
    test_method_get_is_case_insensitive``, both updated from ``assertIs`` to
    ``assertEqual`` + ``assertIsNot`` for exactly this reason.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_featcode_import_mints_nothing(self) -> None:
        """The guard against the import-time mutation coming back -- count-
        agnostic on purpose.

        Before this fix, importing :mod:`pcapkit.const.ftp.command` minted
        :class:`~pcapkit.const.ftp.command.FEATCode` members as a side
        effect of evaluating :class:`~pcapkit.const.ftp.command.Command`'s
        own class body -- each row referencing an upper-case ``FEAT code``
        called ``FEATCode('AUTH')`` etc., and :meth:`FEATCode._missing_`
        minted one the first time. The generator now declares every ``FEAT
        code`` the live IANA registry's own column names as a real member,
        so every :class:`Command` row references one by plain attribute
        access and nothing is minted merely by importing the module.

        Deliberately not a literal member count: the owner ruled against
        that guard on #860, because a hardcoded number breaks whenever IANA
        updates its list -- a regeneration that correctly picks up
        a newly-registered FEAT code would fail it for being *right*. The invariant that survives a table update instead: every
        name in ``__members__`` is a real declaration in the generated
        source, not something built by a call at import time. A
        regeneration moves declarations and members together; only an
        import-time mint would leave a member with no matching declaration.
        """
        from pcapkit.const.ftp import command
        from pcapkit.const.ftp.command import FEATCode

        source = pathlib.Path(command.__file__).read_text(encoding='utf-8')
        self.assertGreater(len(FEATCode.__members__), 0)
        for name in FEATCode.__members__:
            with self.subTest(member=name):
                self.assertRegex(
                    source, rf'(?m)^\s+{re.escape(name)} = ',
                    f'{name!r} is in FEATCode.__members__ but is not declared in '
                    f'{command.__file__!r}, so something minted it at import time')

    def test_command_rows_reference_declared_featcode_members(self) -> None:
        """Every :class:`~pcapkit.const.ftp.command.Command` row naming an
        upper-case ``FEAT code`` must resolve to the *same* declared
        :class:`~pcapkit.const.ftp.command.FEATCode` member as every other
        row naming the same code -- not a fresh, unregistered one apiece,
        which is what calling ``FEATCode(...)`` at class-body-evaluation
        time used to build."""
        from pcapkit.const.ftp.command import Command, FEATCode

        self.assertIs(Command.AUTH.feat, FEATCode.AUTH)  # type: ignore[attr-defined]
        self.assertIs(Command.HOST.feat, FEATCode.HOST)  # type: ignore[attr-defined]
        self.assertIs(Command.LANG.feat, FEATCode.UTF8)  # type: ignore[attr-defined]
        # Two different commands sharing one FEAT code resolve to the one
        # declared member, not two distinct unregistered ones.
        self.assertIs(Command.MLSD.feat, FEATCode.MLST)  # type: ignore[attr-defined]
        self.assertIs(Command.MLST.feat, FEATCode.MLST)  # type: ignore[attr-defined]
        self.assertIs(Command.MLSD.feat, Command.MLST.feat)  # type: ignore[attr-defined]

    def test_featcode_missing_no_longer_mints(self) -> None:
        """The convention pinned across all three open-vocabulary classes:
        an unregistered member's *value* is the caller's own casing,
        unchanged -- ``FEATCode`` never minted any other way, and
        :class:`~pcapkit.const.ftp.command.Command`/:class:`~pcapkit.const.
        http.method.Method` are pinned to match it below."""
        from pcapkit.const.ftp.command import FEATCode

        before = len(FEATCode.__members__)
        first = FEATCode('pypcapkit860probe')
        after = len(FEATCode.__members__)
        second = FEATCode('pypcapkit860probe')

        self.assertEqual(before, after)
        self.assertNotIn('PYPCAPKIT860PROBE', FEATCode.__members__)
        self.assertEqual(first.value, 'pypcapkit860probe')
        self.assertEqual(first, 'pypcapkit860probe')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(repr(first), '<FEATCode [PYPCAPKIT860PROBE]>')

    def test_command_missing_no_longer_mints(self) -> None:
        """Same convention as :class:`~pcapkit.const.ftp.command.FEATCode`'s:
        the *value* is exactly what was observed (``value == 'wire casing'``
        holds), matching ``main``'s own pre-#860 behaviour for this class --
        only the *name* is canonicalised. Verified directly against a
        measured regression risk: swapping the value for the canonicalised
        name (as an earlier revision of this conversion did) would make
        ``Command('xyzw') == 'xyzw'`` false, which never held on ``main``
        and would have been this PR's one real behaviour break."""
        from pcapkit.const.ftp.command import Command, CommandType, ConformanceRequirement

        before = len(Command.__members__)
        first = Command('pypcapkit860probe')
        after = len(Command.__members__)
        second = Command('pypcapkit860probe')

        self.assertEqual(before, after)
        self.assertNotIn('PYPCAPKIT860PROBE', Command.__members__)
        self.assertEqual(first.value, 'pypcapkit860probe')
        self.assertEqual(first, 'pypcapkit860probe')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

        # Every attribute __new__ would have set, read without raising.
        self.assertIsNone(first.feat)
        self.assertIsNone(first.desc)
        self.assertEqual(first.type, CommandType.undefined)
        self.assertEqual(first.conf, ConformanceRequirement.O)
        self.assertEqual(repr(first), '<Command.PYPCAPKIT860PROBE: None>')

    def test_command_get_unknown_no_longer_mints(self) -> None:
        """The value keeps the caller's own casing (see :meth:`Command.
        _unregistered_member`'s own docstring) -- so a repeated call with
        the *same* casing is equal but not identical, while a *different*
        casing is a genuinely different value and correctly not equal. On
        ``main`` minting's cache made both calls return the identical,
        first-seen-casing object regardless; losing that is #860's one
        observable behaviour change here, not a casing change."""
        from pcapkit.const.ftp.command import Command

        before = len(Command.__members__)
        first = Command.get('pypcapkit860probe2')
        after = len(Command.__members__)
        repeated = Command.get('pypcapkit860probe2')
        different_case = Command.get('PYPCAPKIT860PROBE2')

        self.assertEqual(before, after)
        self.assertNotIn('PYPCAPKIT860PROBE2', Command.__members__)
        self.assertEqual(first, 'pypcapkit860probe2')
        self.assertEqual(first, repeated)
        self.assertIsNot(first, repeated)
        self.assertEqual(different_case, 'PYPCAPKIT860PROBE2')
        self.assertNotEqual(first, different_case)

    def test_method_missing_no_longer_mints(self) -> None:
        """Same convention as :class:`~pcapkit.const.ftp.command.FEATCode`'s
        and :class:`~pcapkit.const.ftp.command.Command`'s: an *unregistered*
        member's value is the caller's own casing, with real :class:`str`
        content. This test used to also pin a genuine asymmetry with every
        *registered* member of this class, tracked as GitHub issue #870:
        :meth:`Method.__new__` called ``str.__new__(cls)`` with no argument
        at all, so all 40 declared members' own :class:`str` payload was
        permanently empty regardless of value (``str(Method.GET) == ''``,
        ``Method.GET == 'GET'`` was :obj:`False`) -- true on ``main`` at
        ``60b85e3a4`` as well as when this test was first written. #870
        fixed :meth:`Method.__new__` to ``str.__new__(cls, value)``,
        mirroring :class:`~pcapkit.const.ftp.command.Command`'s own
        ``__new__``, so a registered member now carries its value as its
        :class:`str` payload too -- see
        :mod:`tests.const.test_const_str_payload_870_unit` for the direct
        pin of that fix, registry-wide. What is left here is what this
        test was always really about: the *unregistered* path, which
        already carried real content before #870 (it bypasses ``__new__``
        entirely) and is unaffected by that fix."""
        from pcapkit.const.http.method import Method

        before = len(Method.__members__)
        first = Method('pypcapkit860probe')
        after = len(Method.__members__)
        second = Method('pypcapkit860probe')

        self.assertEqual(before, after)
        self.assertNotIn('PYPCAPKIT860PROBE', Method.__members__)
        self.assertEqual(str(first), 'pypcapkit860probe')
        self.assertEqual(first, 'pypcapkit860probe')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

        # Every attribute __new__ would have set, read without raising.
        self.assertFalse(first.safe)
        self.assertFalse(first.idempotent)
        # Method.__repr__ reads _value_, not _name_ (unlike Command's,
        # which reads _name_ -- see the difference reflected here), so the
        # caller's own casing shows through in the repr too.
        self.assertEqual(repr(first), '<Method.pypcapkit860probe>')

    def test_method_get_unknown_no_longer_mints(self) -> None:
        """Same convention and same reasoning as :meth:`Command.
        _unregistered_member`'s -- the value keeps the caller's own
        casing, so same-casing repeats are equal-not-identical and a
        different casing is correctly not equal."""
        from pcapkit.const.http.method import Method

        before = len(Method.__members__)
        first = Method.get('pypcapkit860probe2')
        after = len(Method.__members__)
        repeated = Method.get('pypcapkit860probe2')
        different_case = Method.get('PYPCAPKIT860PROBE2')

        self.assertEqual(before, after)
        self.assertNotIn('PYPCAPKIT860PROBE2', Method.__members__)
        self.assertEqual(first, 'pypcapkit860probe2')
        self.assertEqual(first, repeated)
        self.assertIsNot(first, repeated)
        self.assertEqual(different_case, 'PYPCAPKIT860PROBE2')
        self.assertNotEqual(first, different_case)

    def test_registered_lookups_are_still_unaffected(self) -> None:
        """A word IANA already assigned still resolves to the same,
        genuinely-registered, identical member every time -- this
        conversion only changes what happens for a word that is not one of
        those.

        ``Method.get`` is probed with its exact registered casing
        (``'GET'``), not the lower-cased ``'get'`` this test used before
        GitHub issue #896: ``Command``'s FTP command codes stay
        case-insensitive per :rfc:`959#section-5`, but the HTTP method
        token :rfc:`9110#section-9.1` covers is case-sensitive, so
        ``Method.get('get')`` no longer resolves to :attr:`Method.GET` --
        see :class:`BespokeGetUnchangedTests`'s
        ``test_method_get_is_now_case_sensitive`` for that behaviour
        directly. ``Method('GET')`` (the constructor, reaching
        :meth:`Method._missing_` rather than :meth:`Method.get`) is
        untouched either way, since #896 is scoped to ``get`` alone.
        """
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.http.method import Method

        self.assertIs(Command('RETR'), Command.RETR)  # type: ignore[attr-defined]
        self.assertIs(Command.get('retr'), Command.RETR)  # type: ignore[attr-defined]
        self.assertIs(Method('GET'), Method.GET)  # type: ignore[attr-defined]
        self.assertIs(Method.get('GET'), Method.GET)  # type: ignore[attr-defined]

    def test_all_three_carry_the_registry_protocol(self) -> None:
        """#842's ruling is that ``get``/``get_all``/``register``/
        ``register_alias`` exist on every registry -- #860 step 2 is what
        actually delivers that for these three."""
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method
        from pcapkit.corekit.enum import EnumRegistry

        for cls in (FEATCode, Command, Method):
            with self.subTest(registry=cls.__name__):
                self.assertTrue(issubclass(cls, EnumRegistry))
                self.assertTrue(callable(getattr(cls, 'get_all', None)))
                self.assertTrue(callable(getattr(cls, 'register', None)))
                self.assertTrue(callable(getattr(cls, 'register_alias', None)))

    def test_commandtype_is_untouched(self) -> None:
        """``CommandType`` -> ``IntEnum`` was floated too.
        Re-opened as `needs: decision` on #860 and settled the other way: it
        keeps ``IntFlag``, because that is how the RFC/IANA data is constructed
        and ``|`` may appear in the CSV. Measured: 2 occurrences
        in the generated data join two kinds with ``/``, e.g. access *and*
        parameter, which a plain ``IntEnum`` cannot represent. Pinned here so
        a future change is noticed as a scope change rather than folded
        silently into some other PR. (``TransportProtocol`` was the other
        half of that same ruling comment -- its own ``auto()`` conversion is
        #860 step 2 PR 2's, covered by
        :class:`AppTypeUnmintConvertedTests` below rather than here.)"""
        from pcapkit.const.ftp.command import CommandType
        from pcapkit.corekit.enum import EnumRegistry

        self.assertFalse(issubclass(CommandType, EnumRegistry))
        self.assertEqual(CommandType.A | CommandType.P, 3)


class BespokeGetReplacementTests(unittest.TestCase):
    """:class:`~pcapkit.const.http.status_code.StatusCode` and
    :class:`~pcapkit.const.ftp.return_code.ReturnCode` are the two of the
    five converted classes whose hand-written ``get()`` -- on the
    ``default == -1`` convention #857/#859 already retired everywhere else
    -- was removed in favour of the base's :meth:`~pcapkit.corekit.enum.
    EnumRegistry.get`, which uses :data:`~pcapkit.corekit.enum.NO_DEFAULT`
    and never mints while resolving ``default`` (#864).

    Verified before this replacement that no caller in :mod:`pcapkit` or
    :mod:`tests` depends on the retired form: ``grep`` found exactly one
    production call site each (:mod:`pcapkit.protocols.application.httpv1`
    and :mod:`pcapkit.protocols.application.ftp`), neither passing a
    ``default`` or a ``str`` key -- both call ``get(<int>)`` with no default,
    which raises identically either way on an unresolvable key. Their own
    ``str``-key ``get()`` branch (look up-or-mint *by name*, keyed on
    ``default``) had no caller anywhere in this tree and is simply gone; the
    base's ``str``-key path does an ordinary name-then-value lookup instead
    and never mints.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_statuscode_get_omitted_default_still_raises(self) -> None:
        """The one production call site's shape: no default passed, so an
        unresolvable key must still raise -- true under both the old
        ``default == -1`` convention and the new ``NO_DEFAULT`` one."""
        from pcapkit.const.http.status_code import StatusCode

        with self.assertRaises(ValueError):
            StatusCode.get(9999)

    def test_statuscode_get_minus_one_is_now_an_ordinary_default(self) -> None:
        """Behaviour change, stated plainly: ``-1`` used to be the sentinel
        for *no default*; it is now just an :class:`int` that -- like any
        other -- is only honoured if it already names a registered member.
        ``-1`` never has, on this registry, so passing it explicitly now
        raises the *original* key's error instead of re-raising because it
        matched the old sentinel."""
        from pcapkit.const.http.status_code import StatusCode

        with self.assertRaises(ValueError) as caught:
            StatusCode.get(9999, -1)
        self.assertIn('9999', str(caught.exception))

    def test_statuscode_get_default_never_mints(self) -> None:
        """#864's ruling, on this registry for the first time: a ``default``
        landing inside a now-converted unassigned range does not resolve to
        an unregistered member the way ``key`` does -- it simply does not
        resolve, and ``key``'s own error propagates."""
        from pcapkit.const.http.status_code import StatusCode

        before = len(StatusCode.__members__)
        with self.assertRaises(ValueError) as caught:
            StatusCode.get(9999, 105)  # 105 is itself in the Unassigned range
        self.assertIn('9999', str(caught.exception))
        self.assertEqual(before, len(StatusCode.__members__))

    def test_returncode_get_omitted_default_still_raises(self) -> None:
        from pcapkit.const.ftp.return_code import ReturnCode

        with self.assertRaises(ValueError):
            ReturnCode.get(9999)

    def test_returncode_get_default_resolves_to_a_real_member(self) -> None:
        """The common, still-supported case: an unresolvable key falls back
        to a ``default`` that already names a real member."""
        from pcapkit.const.ftp.return_code import ReturnCode

        result = ReturnCode.get(9999, 226)
        self.assertIs(result, ReturnCode.CODE_226)  # type: ignore[attr-defined]

    def test_statuscode_and_returncode_gained_get_all_register(self) -> None:
        from pcapkit.const.http.status_code import StatusCode
        from pcapkit.const.ftp.return_code import ReturnCode

        for cls in (StatusCode, ReturnCode):
            with self.subTest(registry=cls.__name__):
                self.assertTrue(callable(getattr(cls, 'get_all', None)))
                self.assertTrue(callable(getattr(cls, 'register', None)))
                self.assertTrue(callable(getattr(cls, 'register_alias', None)))


class BespokeGetUnchangedTests(unittest.TestCase):
    """:class:`~pcapkit.const.ftp.command.Command`,
    :class:`~pcapkit.const.http.method.Method` and
    :class:`~pcapkit.const.pcapng.option_type.OptionType` keep their own
    hand-written ``get()`` in PR 1, because each does real dispatch the
    base's generic ``get()`` does not replicate. :class:`Command` resolves
    case-insensitively (GitHub issue #582 -- ``Command.get('abor')`` must
    return :attr:`Command.ABOR`, not raise), which the base's plain
    ``_member_map_``/``_value2member_map_`` lookup does not do -- swapping in
    the base would silently reintroduce #582. That pin lives in
    :mod:`tests.const.test_const_method_case_sensitive_896_unit`
    (``test_command_get_stays_case_insensitive``).

    :class:`Method` used to resolve case-insensitively the same way (#583),
    but GitHub issue #896 retired that: RFC 9110 Section 9.1 makes the HTTP
    method token case-sensitive, unlike FTP's command codes (RFC 959 Section
    4.1), so ``Method.get('Get')`` no longer returns :attr:`Method.GET` --
    see ``test_method_get_is_now_case_sensitive`` below, which replaces the
    case-insensitive pin this class used to carry for it. ``Method`` still
    keeps its own ``get()`` rather than the base's, because it still needs to
    build an unregistered member preserving the caller's own casing on a
    miss (the base's generic ``get()`` only ever raises or falls back to an
    already-registered ``default`` for a ``str`` key, per
    :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own docstring) -- what
    #896 changed is only whether the lookup that precedes that fallback is
    case-sensitive.

    :class:`OptionType`'s ``get()`` does its own multi-namespace dispatch via
    :attr:`__members_ns__` with no base equivalent at all. These are
    regression guards, not new coverage.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_method_get_is_now_case_sensitive(self) -> None:
        """GitHub issue #896: only the exact registered casing resolves.

        Replaces this class's own ``test_method_get_is_still_case_
        insensitive``, whose title and body pinned the opposite -- that
        ``Method.get('Get')``/``Method.get('get')`` resolved to
        :attr:`Method.GET`. RFC 9110 Section 9.1 makes the method token
        case-sensitive, so a differently-cased probe now builds its own
        unregistered member (preserving the caller's casing, same
        convention as :meth:`Method._unregistered_member`) rather than
        resolving to :attr:`Method.GET`.
        """
        from pcapkit.const.http.method import Method

        self.assertIs(Method.get('GET'), Method.GET)  # type: ignore[attr-defined]
        self.assertTrue(Method.get('GET').safe)

        before = len(Method.__members__)
        for key in ('Get', 'get', 'gEt'):
            with self.subTest(key=key):
                probed = Method.get(key)  # type: ignore[attr-defined]
                self.assertIsNot(probed, Method.GET)
                # Building the pseudo-member never registers it -- 'GET'
                # itself is the only real member these differently-cased
                # names could collide with, and membership does not grow.
                self.assertEqual(len(Method.__members__), before)
                # The caller's own casing survives on the value; only the
                # (unregistered) member's name is canonicalised.
                self.assertEqual(probed.value, key)
                self.assertEqual(probed.name, key.upper())
                # Neither attribute a bare wire token cannot supply is
                # fabricated -- same as any other unregistered member.
                self.assertFalse(probed.safe)
                self.assertFalse(probed.idempotent)

    def test_optiontype_get_namespace_dispatch_is_unchanged(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        self.assertIs(OptionType.get(2, namespace='if'), OptionType.if_name)  # type: ignore[attr-defined]
        self.assertIs(OptionType.get(2, namespace='epb'), OptionType.epb_flags)  # type: ignore[attr-defined]


class AppTypeUnmintConvertedTests(unittest.TestCase):
    """GitHub issue #860 step 2, PR 2 (the second and final PR of this step):
    :class:`~pcapkit.const.reg.apptype.apptype.AppType` and its four
    per-transport registries -- :class:`~pcapkit.const.reg.apptype.tcp.TCP`,
    :class:`~pcapkit.const.reg.apptype.udp.UDP`,
    :class:`~pcapkit.const.reg.apptype.sctp.SCTP`,
    :class:`~pcapkit.const.reg.apptype.dccp.DCCP` -- brought onto
    :class:`~pcapkit.corekit.enum.EnumRegistry` and stopped from minting.

    Largest of the 9 bespoke classes #860 step 2 converts: measured on
    ``c411d072a`` by an AST walk over :meth:`AppType._missing_`, 766
    range-bounded branches -- 754 ``unassigned_<port>`` and 4
    ``reserved_<port>`` placeholders, plus 8 branches naming a real service
    IANA assigns to a whole span rather than to one declared member each
    (``x11`` for TCP and again for UDP, ``active-net``, ``satvid-datalnk``,
    ``vrml-multi-use``, ``ircu``, ``swx``, ``flex-lm``) -- plus one more,
    independent mint site inside :meth:`AppType.get` itself
    (``PORT_<port>_<transport>``, labelled ``'unknown'``, for a port neither
    ``_missing_``'s ranges nor the registry's own declared members cover).

    A deliberate scope decision, stated here because a reviewer could
    reasonably expect the ``FEATCode`` precedent instead: the 8 real-name
    spans above convert to :meth:`~pcapkit.corekit.enum.
    EnumRegistry._unregistered_member` exactly like the 758 placeholder
    spans, *not* declared as real, individually-listed members the way #860
    step 2's PR 1 declared ``FEATCode``'s 15. ``FEATCode``'s fix addressed a
    *different* defect -- a const module minting members as a side effect of
    merely being imported, which does not exist here, since every one of
    these 766 spans mints only on an actual port lookup -- and the owner's
    ruling for the whole ``AppType`` family draws no distinction between a
    real name and a placeholder: GitHub issue #860 settled that ``get()``
    must not mint regardless of whether the value it would construct is a
    genuine IANA-registered name or a manufactured placeholder, because
    only ``register()`` may create a new entry and ``get()`` never has
    enough information to build one itself. A lookup resolving
    ``TCP(6010)`` after this PR therefore returns an *unregistered* ``x11``
    member -- correct as a service name, but absent from
    ``__members__``/``_value2member_map_`` until someone calls
    ``TCP.register(6010, 'x11')`` explicitly.

    Unlike every bespoke class #860 step 2's PR 1 converted,
    :meth:`AppType.get` already existed before this PR and does genuine
    transport-protocol dispatch through :meth:`~AppType._dispatch` -- so,
    unlike :class:`~pcapkit.const.http.status_code.StatusCode`/
    :class:`~pcapkit.const.ftp.return_code.ReturnCode`, it keeps its own
    ``get()`` rather than being replaced by the base's; and, unlike
    :class:`~pcapkit.const.ftp.command.Command`/
    :class:`~pcapkit.const.http.method.Method`/
    :class:`~pcapkit.const.pcapng.option_type.OptionType`, its own
    ``_unregistered_member`` override reconstructs three attributes
    (``svc``, ``port``, ``proto``) rather than one or two, because
    :meth:`AppType.__new__` sets all three and none is optional for
    :meth:`__repr__`/:meth:`__str__`/:meth:`__int__`/the comparison
    operators/:attr:`~AppType.aliases` to run on the result without raising.

    :meth:`AppType.register` is new on this PR. ``AppType`` already had a
    working ``get``/``get_all``/``register_alias`` of its own, but never a
    working ``register`` -- and the base's generic one (which calls
    ``cls.__new__(cls, value)`` with only ``value``) would have built a
    member with ``svc='<null>'`` and ``proto=TransportProtocol.undefined``,
    silently wrong, the moment this class mixed in
    :class:`~pcapkit.corekit.enum.EnumRegistry` without an override. Scoped
    like :meth:`~AppType.register_alias` to **this** per-transport registry
    rather than dispatched through :meth:`~AppType._dispatch`, for the same
    reason register_alias already was: minting on one transport must never
    leak onto a transport IANA never assigned the service to.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_apptype_family_carries_the_registry_protocol(self) -> None:
        """#842's ruling is that ``get``/``get_all``/``register``/
        ``register_alias`` exist on every registry -- #860 step 2 PR 2 is
        what actually delivers that for this family, including ``register``,
        which none of the five had a working version of before this PR."""
        from pcapkit.const.reg.apptype.apptype import AppType
        from pcapkit.const.reg.apptype.dccp import DCCP
        from pcapkit.const.reg.apptype.sctp import SCTP
        from pcapkit.const.reg.apptype.tcp import TCP
        from pcapkit.const.reg.apptype.udp import UDP
        from pcapkit.corekit.enum import EnumRegistry

        for cls in (AppType, TCP, UDP, SCTP, DCCP):
            with self.subTest(registry=cls.__name__):
                self.assertTrue(issubclass(cls, EnumRegistry))
                self.assertTrue(callable(getattr(cls, 'get_all', None)))
                self.assertTrue(callable(getattr(cls, 'register', None)))
                self.assertTrue(callable(getattr(cls, 'register_alias', None)))
                self.assertTrue(callable(getattr(cls, '_unregistered_member', None)))

    def test_unassigned_range_resolves_without_minting(self) -> None:
        """226 sits in the base registry's 225-241 ``reserved`` span, which
        names no transport protocol, so it answers every one of the four
        per-transport registries identically -- the same shape as
        :class:`UnassignedRangeDoesNotMintTests` above, generalised to a
        registry whose ``_unregistered_member`` reconstructs three
        attributes rather than the generic zero."""
        from pcapkit.const.reg.apptype.dccp import DCCP
        from pcapkit.const.reg.apptype.sctp import SCTP
        from pcapkit.const.reg.apptype.tcp import TCP
        from pcapkit.const.reg.apptype.udp import UDP

        for cls in (TCP, UDP, SCTP, DCCP):
            with self.subTest(registry=cls.__name__):
                # NOTE: ``_value2member_map_`` is keyed by AppType's own
                # formatted ``_value_`` string (``'svc [port - proto]'``),
                # never by the bare port -- so the side table that would grow
                # from a mint here is ``__registry__``, checked below, not
                # this one.
                self.assertFalse(cls.__registry__.getlist(226))
                before = len(cls.__members__)

                first = cls(226)
                after_one = len(cls.__members__)
                second = cls(226)
                after_two = len(cls.__members__)

                self.assertEqual(before, after_one)
                self.assertEqual(before, after_two)
                self.assertEqual(first, second)
                self.assertIsNot(first, second)
                self.assertEqual(first.svc, 'reserved')
                self.assertEqual(first.port, 226)
                self.assertFalse(cls.__registry__.getlist(226))
                self.assertNotIn('reserved', cls.__members__)

    def test_out_of_bound_port_still_fails(self) -> None:
        from pcapkit.const.reg.apptype.tcp import TCP

        with self.assertRaises(ValueError):
            TCP(1 << 32)
        with self.assertRaises(ValueError):
            TCP(-1)

    def test_named_transport_span_still_dispatches_and_does_not_mint(self) -> None:
        """GitHub issue #760's own regression: 6000-6063 is ``x11`` on TCP
        and ``x11`` on UDP too, both testing ``cls.__transport__`` so a UDP
        lookup cannot come back carrying TCP's label -- and 6665-6669 is the
        sharper case, ``ircu`` on TCP but IANA's own ``reserved`` marker on
        UDP for the *same* span, so a merged branch could not have kept both.
        Converting ``extend_enum(...)`` to ``_unregistered_member(...)`` left
        every ``if``/``cls.__transport__ is ...`` test untouched -- this pins
        that the dispatch survived the conversion, not just that minting
        stopped."""
        from pcapkit.const.reg.apptype.tcp import TCP
        from pcapkit.const.reg.apptype.udp import UDP

        tcp_before = len(TCP.__members__)
        udp_before = len(UDP.__members__)

        tcp_x11 = TCP(6010)
        udp_x11 = UDP(6010)
        self.assertEqual(tcp_x11.svc, 'x11')
        self.assertEqual(udp_x11.svc, 'x11')
        self.assertEqual(len(TCP.__members__), tcp_before)
        self.assertEqual(len(UDP.__members__), udp_before)

        tcp_ircu = TCP(6667)
        udp_reserved = UDP(6667)
        self.assertEqual(tcp_ircu.svc, 'ircu')
        self.assertEqual(udp_reserved.svc, 'reserved')
        self.assertEqual(len(TCP.__members__), tcp_before)
        self.assertEqual(len(UDP.__members__), udp_before)

    def test_get_second_mint_site_no_longer_mints(self) -> None:
        """54321 is not a declared member and not inside any of
        ``_missing_``'s ranges either, so it used to reach :meth:`AppType.
        get`'s own, second, independent ``extend_enum(...)`` call --
        distinct from the one inside ``_missing_``, and easy to miss when
        converting only the latter (exactly what round 2 review of #860 step
        2 PR 1 caught on :class:`~pcapkit.const.pcapng.option_type.
        OptionType` for the same reason)."""
        from pcapkit.const.reg.apptype.tcp import TCP

        before = len(TCP.__members__)
        first = TCP.get(54321)
        after = len(TCP.__members__)
        second = TCP.get(54321)

        self.assertEqual(before, after)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(first.svc, 'unknown')
        self.assertEqual(first.port, 54321)
        from pcapkit.const.reg.apptype.apptype import TransportProtocol
        self.assertIs(first.proto, TransportProtocol.tcp)
        self.assertFalse(TCP.__registry__.getlist(54321))

    def test_missing_direct_call_still_raises_for_the_same_port(self) -> None:
        """The asymmetry this PR leaves in place, deliberately: a direct
        ``TCP(54321)`` has no ``get()`` around it to catch ``_missing_``'s
        :obj:`None` answer and build an ``'unknown'`` member from it, so it
        still raises exactly as it did on ``main`` -- only :meth:`AppType.
        get` gained the fallback, matching the constructor's own long-
        standing behaviour of raising rather than minting for a value inside
        ``0..65535`` but outside every declared member and every
        ``_missing_`` span."""
        from pcapkit.const.reg.apptype.tcp import TCP

        with self.assertRaises(ValueError):
            TCP(54321)

    def test_unregistered_member_reconstructs_every_attribute(self) -> None:
        from pcapkit.const.reg.apptype.apptype import TransportProtocol
        from pcapkit.const.reg.apptype.tcp import TCP

        before = len(TCP.__members__)
        member = TCP._unregistered_member(59998, 'probe-svc', TransportProtocol.tcp)
        after = len(TCP.__members__)

        self.assertEqual(before, after)
        self.assertEqual(member.svc, 'probe-svc')
        self.assertEqual(member.port, 59998)
        self.assertIs(member.proto, TransportProtocol.tcp)
        self.assertEqual(int(member), 59998)
        self.assertEqual(member.aliases, ())
        self.assertEqual(repr(member), '<TCP.probe-svc: 59998 [tcp]>')
        self.assertEqual(str(member), 'probe-svc [59998 - tcp]')
        self.assertFalse(TCP.__registry__.getlist(59998))
        self.assertNotIn('probe-svc', TCP.__members__)

    def test_unregistered_member_on_apptype_itself_raises(self) -> None:
        """:class:`AppType` holds no members of its own -- the same guard
        :meth:`AppType.__new__` and :meth:`AppType.register` both already
        enforce."""
        from pcapkit.const.reg.apptype.apptype import AppType

        with self.assertRaises(ValueError):
            AppType._unregistered_member(1, 'x')

    def test_register_mints_a_real_member_and_refuses_a_duplicate_port(self) -> None:
        """``AppType._value_`` is the formatted ``'svc [port - proto]'``
        string, not the bare port -- so ``TCP(port)`` is not how a
        registered member is reached at all, on ``main`` as well as here
        (verified directly: ``TCP(80)`` raises for the real, declared
        ``http`` member too). ``TCP.get(port)`` and the ``__registry__``
        side table are the two things a real ``register()`` call is checked
        against below."""
        from pcapkit.const.reg.apptype.tcp import TCP

        port = 59991
        self.assertFalse(TCP.__registry__.getlist(port))

        member = TCP.register(port, 'pypcapkit-860-probe')
        self.assertEqual(member.svc, 'pypcapkit-860-probe')
        self.assertEqual(member.port, port)
        self.assertIn(member, TCP.__registry__.getlist(port))
        self.assertIn(member._value_, TCP._value2member_map_)  # type: ignore[misc]
        self.assertIs(TCP.pypcapkit_860_probe, member)
        self.assertIs(TCP.get(port), member)

        with self.assertRaises(ValueError):
            TCP.register(port, 'again')
        with self.assertRaises(ValueError):
            TCP.register(60005, '123')  # sanitises to '123', not a valid identifier

    def test_register_on_apptype_itself_raises(self) -> None:
        from pcapkit.const.reg.apptype.apptype import AppType

        with self.assertRaises(ValueError):
            AppType.register(1234, 'x')

    def test_register_alias_still_works_after_the_sanitizer_refactor(self) -> None:
        """:meth:`AppType.register`/:meth:`AppType.register_alias` now share
        :meth:`AppType._sanitize_identifier` rather than each carrying its
        own copy of the sanitising steps -- this is the regression check
        that the refactor changed nothing observable about the alias path."""
        from pcapkit.const.reg.apptype.tcp import TCP

        port = 59992
        canonical = TCP.register(port, 'pypcapkit-860-canonical')
        alias = TCP.register_alias(port, 'pypcapkit-860-alias')

        self.assertEqual(alias.port, port)
        self.assertIn(canonical, alias.aliases)
        self.assertIn(alias, canonical.aliases)
        self.assertIs(TCP.pypcapkit_860_alias, alias)

        with self.assertRaises(ValueError):
            TCP.register_alias(60006, 'no canonical member yet')

    def test_apptype_get_dispatches_via_proto_without_minting(self) -> None:
        from pcapkit.const.reg.apptype.apptype import AppType
        from pcapkit.const.reg.apptype.tcp import TCP

        before = len(TCP.__members__)
        member = AppType.get(80, proto='tcp')
        after = len(TCP.__members__)

        self.assertIs(member, TCP.get(80))
        self.assertEqual(before, after)

    def test_apptype_unrecognised_proto_is_still_refused(self) -> None:
        """A ``proto`` naming no registry at all -- not one of the two real
        collision cases ``auto()`` introduced, just an ordinary invalid value
        -- is still refused by :meth:`AppType._dispatch`, unaffected by this
        PR. (Deliberately not a composite like ``tcp | udp``: under
        ``auto()`` that now equals ``sctp`` numerically and dispatches
        there rather than raising, which is the one accepted, explicitly
        untested consequence of the ``auto()`` change -- see
        :class:`TransportProtocolAutoTests`.)"""
        from pcapkit.const.reg.apptype.apptype import AppType

        with self.assertRaises(ValueError):
            AppType.get(80, proto=99)


class TransportProtocolAutoTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`'s
    ``auto()`` conversion, #860 step 2 PR 2's other change. The owner ruled on
    #860 that, since ``|`` composition is no longer allowed, ``auto()`` in place
    of power-of-two spacing is the right move -- a breaking change, but an
    accepted one. On the one behavioural consequence -- a hand-composed
    ``tcp | udp`` now equalling ``sctp`` numerically (``1 | 2 == 3``), where it
    used to name no member at all and be refused as a whole -- the same thread
    settled that no test should pin it: the path is obsolete after the breaking
    change, and a test would preserve it as though it still mattered. So this class deliberately covers only the values and the
    stale comment's removal, not the composition consequence: no test here
    calls ``_dispatch`` with a composed value at all, unlike
    :meth:`AppTypeUnmintConvertedTests.
    test_apptype_unrecognised_proto_is_still_refused`, which uses an
    ordinary invalid value instead precisely to stay clear of it.

    """

    def test_values_are_sequential_from_zero(self) -> None:
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertEqual(int(TransportProtocol.undefined), 0)
        self.assertEqual(int(TransportProtocol.tcp), 1)
        self.assertEqual(int(TransportProtocol.udp), 2)
        self.assertEqual(int(TransportProtocol.sctp), 3)
        self.assertEqual(int(TransportProtocol.dccp), 4)

    def test_still_not_a_registry(self) -> None:
        """Unaffected by this PR: ``TransportProtocol`` never minted through
        :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`, and
        does not mix in :class:`~pcapkit.corekit.enum.EnumRegistry` now
        either -- only ``AppType`` and its four transport subclasses do."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol
        from pcapkit.corekit.enum import EnumRegistry

        self.assertFalse(issubclass(TransportProtocol, EnumRegistry))

    def test_get_still_refuses_an_unrecognised_name(self) -> None:
        """GitHub PR #836's ruling against extending ``TransportProtocol``
        at all is untouched by the ``auto()`` change -- :meth:`~pcapkit.const.
        reg.apptype.apptype.TransportProtocol.get` still has no ``_missing_``
        of its own and still refuses outright rather than minting.

        :exc:`KeyError`-shaped since GitHub issue #923, which retired the
        override's ``KeyError`` -> ``ValueError`` conversion; the refusal itself
        is what this test is about and that is unchanged."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        with self.assertRaises(KeyError):
            TransportProtocol.get('not-a-real-transport')

    def test_stale_power_of_two_comment_is_gone(self) -> None:
        """Per GitHub issue #860: the in-code comment claiming
        the values "must keep" power-of-two spacing contradicted the PR #836
        ruling that nothing composes a ``TransportProtocol`` any
        more, and is deleted rather than merely superseded -- checked
        against the generated source itself, not the docstring here, so a
        regeneration that reintroduces it fails this test."""
        import pcapkit.const.reg.apptype.apptype as apptype_module

        source = pathlib.Path(apptype_module.__file__).read_text(encoding='utf-8')
        self.assertNotIn('must keep', source)
        self.assertNotIn('the power-of-two spacing the values', source)


if __name__ == '__main__':
    unittest.main()
