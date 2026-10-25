# -*- coding: utf-8 -*-
"""Regression tests for GitHub issue #775's tier 1: the miss path must not mint.

The ruling on #775 is that no registry creates a registered enum out of an
unrecognised or unregistered value, however legitimate but unbounded the values
are, unless the user or caller explicitly created it -- and lookup never counts as
asking for a name, only the :meth:`register` classmethod does. Without the fix,
both ``get()``'s string path and ``_missing_``'s bounded-but-unassigned range
branch call :func:`aenum.extend_enum`, permanently growing the registry for a
value nobody asked to be named. Measured on a tree without the fix:
:class:`~pcapkit.const.arp.hardware.Hardware`'s ``__members__`` moved from 41
entries to 42 after a single ``Hardware(40)`` (40 sits in the documented
39-255 "Unassigned" range) and stayed at 42 on a second call -- growth that
never reverses for the life of the process, and that a long-running capture
walking many such values would accumulate without bound.

Tier 1 covers the shared ``get()`` template in :mod:`pcapkit.vendor.default`
and the ``_missing_`` range-branch :meth:`~pcapkit.vendor.
default.Vendor.process` assembles -- see that module for those hunks -- and so
the registries that inherit both unmodified, which this module's
:data:`REGISTRIES_WITH_UNASSIGNED_RANGES` and :data:`ALL_REGISTRIES` enumerate.

Tier 1 fixes the *mechanism* (a lookup should never mint); tier 2 decides,
registry by registry, which ``_missing_`` bodies mint something worth keeping.
The owner's mint/unmint criterion was settled on PR #847 and confirmed on #775
as the core of the ruling: a name is minted when it is the final concrete name
an assignment gave, and left unminted when it is only a notation for the
readers. A dynamically or statically assigned range is as unspecified as any
other -- it gets concrete names when something assigns them -- so its
placeholder is notation, not a name worth registering. Applied registry by
registry to every ``_missing_`` calling :func:`~aenum.extend_enum` -- measured
by an AST walk over ``pcapkit/const/*.py`` rather than estimated -- the ruling
converts them (:data:`RULING_CONVERTED_REGISTRIES` below).
:class:`~pcapkit.const.mh.cga_type.CGAType` mints, for a different
reason: its ``Tag_<hex>`` mint is not an IANA-style range at all (see its own
module for why), so the ruling does not cover it.

GitHub issue #860 (step 2) brings the bespoke classes -- the vendor files that
replace the shared template wholesale, and what they generate -- onto
:class:`~pcapkit.corekit.enum.EnumRegistry` and converts their branches -- see
:data:`BESPOKE_UNMINT_CONVERTED_REGISTRIES` and
:class:`BespokeOpenVocabularyUnmintConvertedTests` below. Two distinct
shapes:

Range-bounded registries whose mint used a manufactured placeholder label
(``Unassigned``, ``Unknown_%d``, ``opt_unknown_%d``):
:class:`~pcapkit.const.http.status_code.StatusCode`,
:class:`~pcapkit.const.ftp.return_code.ReturnCode`,
:class:`~pcapkit.const.ftp.return_code.ResponseKind`,
:class:`~pcapkit.const.ftp.return_code.GroupingInformation` and
:class:`~pcapkit.const.pcapng.option_type.OptionType`,
unambiguous under the mint/unmint criterion.
Each carries a custom ``__new__`` with extra per-member attributes (unlike
any of the tier-2 registries above), so each has its own
``_unregistered_member`` override reconstructing those attributes rather
than the shared base's generic one, and :class:`StatusCode` and
:class:`ReturnCode` use the base's ``get()`` rather than a hand-written one
-- see :class:`BespokeGetReplacementTests` for the ``default == -1`` ->
``NO_DEFAULT`` behaviour change that implies.
:class:`OptionType` keeps its own ``get()`` (genuine multi-namespace
dispatch the base does not replicate), and both its int/namespace path and
its ``str`` path are ``_unregistered_member`` calls too -- the same
"leaving ``get()`` minting while ``_missing_`` does not contradicts the
ruling" argument that converts :class:`Command`'s and :class:`Method`'s own
``get()`` mint sites below; see
:meth:`BespokeUnmintConvertedRegistriesTests.
test_optiontype_get_int_path_no_longer_mints`,
``..._namespace_path_...`` and ``..._str_path_...``.

Open-vocabulary registries whose mint used the exact, unmodified observed
value as its own name rather than any manufactured label:
:class:`~pcapkit.const.ftp.command.FEATCode`,
:class:`~pcapkit.const.ftp.command.Command` and
:class:`~pcapkit.const.http.method.Method` -- a single ``_missing_`` branch each,
genuinely ambiguous under the criterion, since nothing about them is a
manufactured placeholder. GitHub issue #860 is where the owner settled it:
``get()`` must not mint, because only ``register()`` creates a new registry
entry -- for these registries only IANA-registered values are legitimate,
and ``get()`` does not have enough information to construct one itself.
That rule is about ``get()`` in its own right, and it extends just as much
to ``_missing_`` -- :class:`Command` needs ``feat``/``desc``/``type``/``conf``
and :class:`Method` needs ``safe``/``idempotent``, neither of which a bare
wire string carries -- so both classes' own ``get()`` (a second, independent
mint site bypassing ``_missing_`` entirely) converts too, alongside
``_missing_``. :class:`FEATCode` has no custom ``__new__``, and its
case-insensitive ``get`` (GitHub issue #903's audit, per
:rfc:`5797#section-2`) never calls ``cls(key)``, so only its one
``_missing_`` branch is in play.

GitHub issue #860 step 2's PR 2 covers
:class:`~pcapkit.const.reg.apptype.apptype.AppType` and its per-transport
registries (:class:`~pcapkit.const.reg.apptype.tcp.TCP`,
:class:`~pcapkit.const.reg.apptype.udp.UDP`,
:class:`~pcapkit.const.reg.apptype.sctp.SCTP`,
:class:`~pcapkit.const.reg.apptype.dccp.DCCP`), which mix in
:class:`~pcapkit.corekit.enum.EnumRegistry` and mint on neither of
AppType's mint sites -- its ``_missing_`` branches, and the one more inside
``get()`` itself. See :class:`AppTypeUnmintConvertedTests` below, including
the deliberate scope decision on those branches that name a real (if
IANA-assigned to a whole span rather than declared individually) service rather
than a placeholder.

Untouched, per the owner's ruling on #860 settling the ``needs: decision`` that
issue re-opened: :class:`~pcapkit.const.ftp.command.CommandType` keeps
``IntFlag``, because that is how the RFC/IANA data is constructed and ``|`` may
appear in the CSV -- measured, 2 occurrences in
the generated data join two kinds with ``/`` and would break under a plain
``IntEnum``; see :class:`BespokeOpenVocabularyUnmintConvertedTests`'s own
``test_commandtype_is_untouched``.
:class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`, by contrast,
is not a ``Flag`` -- on a different ruling than CommandType's, not the same
one. GitHub PR #836 retires ``|``-composite decoding: ``TransportProtocol``
not being a ``Flag``, a ``|``-joined value is not parsed and accepted but
treated as a whole, instead of being split. GitHub issue #860 draws the
further consequence: the power-of-two spacing exists only for the
``tcp | udp``-style code that composition served, and since the logic does
not accept that piping, ``auto()`` is the expected numbering. So it numbers
its members sequentially from 0 -- ``undefined`` a direct, explicit ``0``,
the rest continuing from it via ``auto()`` with no ``_start_`` needed, per
the owner's own further ruling settling the declaration shape. The owner
also ruled, on #860, that no test should pin the one behavioural
consequence, since it is an obsolete path left by an accepted breaking
change -- and it is a real consequence, not a refusal: a hand-composed
``tcp | udp`` (or a bare, uncomposed ``3``) silently resolves as ``sctp``'s
own value through :meth:`AppType._dispatch`. None of the tests below pin
that, per the same ruling.

GitHub issue #775 also converts the attributed branches: every one of
:class:`~pcapkit.const.reg.ethertype.EtherType`'s range branches, and
:class:`~pcapkit.const.ipx.socket.Socket`'s ``Registered by Xerox`` one,
return :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` too --
PR #878 scoped it this way: keeping the existing hex-suffixed name, since the
conversion is about not registering rather than renaming. So each keeps the
hex-suffixed name (``Xyplex_0x0888``, not a bare ``Xyplex``) even though it
does not register -- both are wholly converted like those in
:data:`RULING_CONVERTED_REGISTRIES`, and
:class:`EtherTypeMixedMintTests`/:class:`IPXSocketMixedMintTests` below
prove that their attributed-vendor probes do not mint. The one
consequence worth naming: this reintroduces the exact "manufactured,
value-suffixed name" shape :func:`is_manufactured` exists to flag, on calls
that are safe because :meth:`_unregistered_member` never registers
regardless of what its ``name`` argument looks like -- see
:func:`_is_hex_suffixed_unregistered_name` in
:class:`UnregisteredMemberNameIsBareTests` for the scoped exemption this
requires, keyed on the ``name`` argument's own shape rather than on the
files it happens to live in.

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

#: (module, class name) for every one of tier 1's registries whose vendor
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

#: Every one of tier 1's registries -- every generated ``const/`` module
#: whose vendor crawler inherits the shared ``get()``/``register()``/
#: ``_unregistered_member()`` template from :mod:`pcapkit.vendor.default`
#: unmodified. Derived the same way as :data:`ALL_REGISTRIES` above, just
#: without narrowing to those with an unassigned range: every vendor file
#: under :mod:`pcapkit.vendor` that is not one of those which replace the
#: shared template wholesale (and not one of the ``AppType`` transport
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


#: (module, class name) for every registry the owner's #775/#847 ruling
#: converts outright: every ``_missing_`` branch that would mint via
#: :func:`~aenum.extend_enum` returns :meth:`~pcapkit.corekit.
#: enum.EnumRegistry._unregistered_member` instead, because what it would
#: mint is a bare status word (``Unassigned``, ``Reserved [...]``, ``Reserved
#: for Private/Experimental Use``, ``Unspecified in the IANA registry``, and
#: similar) rather than a name anyone assigned. Derived from an AST walk over
#: the modules that mint without the fix, including the attributed branches
#: of :class:`~pcapkit.const.reg.ethertype.EtherType` and
#: :class:`~pcapkit.const.ipx.socket.Socket` (see :data:`ETHERTYPE_UNASSIGNED_PROBES` and
#: :data:`IPX_SOCKET_UNASSIGNED_PROBES`). Not listed: the bespoke classes
#: GitHub issue #860 converts instead (:class:`~pcapkit.const.reg.apptype.
#: apptype.AppType`, :class:`~pcapkit.const.http.status_code.StatusCode`,
#: :mod:`pcapkit.const.ftp.return_code`, :mod:`pcapkit.const.ftp.command`,
#: :class:`~pcapkit.const.http.method.Method`, :class:`~pcapkit.const.pcapng.
#: option_type.OptionType` -- see the module docstring), and :class:
#: `~pcapkit.const.mh.cga_type.CGAType`, which the ruling does not cover
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
#: ``_missing_`` masks it. One reason holds registries out of this list: some
#: have no reachable gap at all -- the same situation :data:`ALL_REGISTRIES`
#: already documents for :class:`~pcapkit.const.hip.transport.Transport`:
#: every value inside the guard's own bounds names a real member, so
#: ``_missing_`` can never actually run for them (e.g. :class:`~pcapkit.const.
#: ipv4.tos_del.ToSDelay` is bounded to ``0 <= value <= 1`` and both 0 and 1
#: are declared). They are proved by :class:`RulingConversionSourceTests` (a
#: source sweep) instead.
#:
#: :class:`~pcapkit.const.reg.ethertype.EtherType` is in this list because
#: :meth:`pcapkit.vendor.reg.ethertype.EtherType.process` tests the narrower
#: 0x0101-0x01FF range ("Old Xerox Experimental...") before the wider
#: 0x0000-0x05DC branch that contains it (GitHub issue #862, fixed by #865),
#: so its *first* converted branch by source order is directly probeable like
#: any other reachable-gap registry's, as
#: :class:`~pcapkit.const.ipx.socket.Socket`'s is below. Without that
#: ordering the branch is masked, and a naive probe would silently exercise
#: the wrong one. See :data:`ETHERTYPE_UNASSIGNED_PROBES`'s comment for the
#: probe itself, also covered explicitly by :class:`EtherTypeMixedMintTests`.
#: Neither registry is mixed -- see that class's own docstring.
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
#: to -- converts too (#775); :data:`ETHERTYPE_FORMERLY_KEPT_PROBE` pins one
#: (``Xyplex``) as a regression guard that it does not mint.
#:
#: "Old Xerox Experimental" (0x0101-0x01FF) is a strict subset of the wider
#: "IEEE802.3 Length Field" branch (0x0000-0x05DC). :meth:`pcapkit.vendor.reg.
#: ethertype.EtherType.process` tests the narrower range first (GitHub issue
#: #862, fixed by #865 -- the same shape of ordering bug GitHub issue #841
#: found in :mod:`pcapkit.const.ipx.socket`), so 0x0101 resolves to Old Xerox
#: and is directly probeable. It is included below alongside ``DEC
#: Unassigned``, giving it the same behavioural no-mint proof
#: :class:`EtherTypeMixedMintTests` gives DEC Unassigned -- stronger than a
#: source-text check, an order-insensitive string search that would keep
#: passing even if the ordering regressed.
ETHERTYPE_OLD_XEROX_LABEL = 'Old_Xerox_Experimental_values_Invalid_as_an_Ethertype_since_1983'
ETHERTYPE_UNASSIGNED_PROBES = {
    0x8039: 'DEC_Unassigned',
    0x0101: ETHERTYPE_OLD_XEROX_LABEL,
}
#: An attributed vendor block -- Xyplex, 0x0888 -- whose company name serves as
#: the name of a proprietary protocol that has none of its own (#775, #847).
#: It converts like the unassigned rows, keeping the hex-suffixed name exactly
#: as the crawler renders it (PR #878 scoped it this way: keeping the existing
#: hex-suffixed name, since the conversion is about not registering rather
#: than renaming), so despite its name this pins that the probe does not
#: mint. Kept as its
#: own constant, distinct from :data:`ETHERTYPE_UNASSIGNED_PROBES`, because
#: :class:`EtherTypeMixedMintTests` below wants it named individually in
#: its own regression test.
ETHERTYPE_FORMERLY_KEPT_PROBE = (0x0888, 'Xyplex_0x0888')

#: :class:`~pcapkit.const.ipx.socket.Socket` probes for the owner's #775/#847
#: ruling: ``Experimental`` and the dynamically/statically assigned labels
#: convert, as notation for the reader rather than a final concrete assigned
#: name. ``Registered by Xerox``, the company one, is pinned by
#: :data:`IPX_SOCKET_FORMERLY_KEPT_PROBE`.
IPX_SOCKET_UNASSIGNED_PROBES = {
    0x0025: 'Experimental',
    0x4001: 'Dynamically Assigned Socket Numbers',
    0x8001: 'Statically Assigned Socket Numbers',
    0x0BBA: 'Dynamically Assigned',
}
#: The mirror of :data:`ETHERTYPE_FORMERLY_KEPT_PROBE` for
#: :class:`~pcapkit.const.ipx.socket.Socket`: ``Registered by Xerox`` also
#: converts (#775), keeping its hex-suffixed name.
IPX_SOCKET_FORMERLY_KEPT_PROBE = (0x0010, 'Registered by Xerox_0x0010')


def _first_unregistered_value(cls: 'type') -> 'Optional[int]':
    """The first value :meth:`cls._missing_ <object._missing_>` converts to a
    throwaway :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
    pseudo-member, read from the class's own compiled ``_missing_`` by AST
    rather than hardcoded.

    Handles both shapes the generated ``_missing_`` takes: a per-range branch (``if lo <= value
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


def _mintable_value(cls: 'type', preferred: 'int') -> 'Optional[int]':
    """``preferred`` if ``cls.register`` may mint it, else the highest value it may.

    ``register`` refuses what ``_validate_value`` refuses (#1816). Every
    registry this is used on checks a range ``0`` to some top, so the top is
    found by bisection on that hook, then stepped down past any member.
    :obj:`None` if every value in range already has a member.

    """
    def legal(value: 'int') -> 'bool':
        try:
            cls._validate_value(value)  # type: ignore[attr-defined]
        except ValueError:
            return False
        return True

    if legal(preferred) and preferred not in cls._value2member_map_:  # type: ignore[attr-defined]
        return preferred
    low, high = 0, preferred
    while low < high:
        mid = (low + high + 1) // 2
        if legal(mid):
            low = mid
        else:
            high = mid - 1
    while low in cls._value2member_map_:  # type: ignore[attr-defined]
        low -= 1
    return low if legal(low) else None


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
        default landing in a bounded-unassigned range does not return the
        pseudo-member the int path does -- it simply does not resolve, and
        the original key's own error propagates instead. That is exactly the
        cost the owner accepted on #864 in choosing a value-only lookup over
        ``cls(default)`` -> ``_missing_``: a default naming a value with no
        registered member does not resolve, on every registry."""
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
        on every one of tier 1's registries, the full set the shared
        template reaches (:data:`ALL_105_REGISTRIES`), not only those
        with a bounded-unassigned range. A high, fixed value is deliberately
        outside any registry's assigned codes, so this cannot collide with
        anything either the CSV seeded or a sibling test minted.

        ``register`` refuses a value outside the range a registry's
        ``_missing_`` checks (#1816), and most bound themselves to 16 bits
        or fewer. So the fixed value is used where the range reaches it, and
        elsewhere the highest value in range that no member carries. A
        registry whose whole range is assigned has nothing left to mint, and
        must refuse the fixed value instead.

        """
        from pcapkit.utilities.exceptions import EnumValueError

        name = 'PyPCAPKit_775_sweep'
        preferred = 0x6E7A0001  # arbitrary, outside most registries' own domains

        for module_name, class_name in ALL_105_REGISTRIES:
            with self.subTest(registry=class_name):
                cls = getattr(importlib.import_module(module_name), class_name)
                value = _mintable_value(cls, preferred)
                if value is None:
                    before = len(cls.__members__)
                    with self.assertRaises(EnumValueError):
                        cls.register(preferred, name)
                    self.assertEqual(len(cls.__members__), before)
                    continue
                self.addCleanup(_purge_member, cls, name, value)

                before = len(cls.__members__)
                new = cls.register(value, name)
                after = len(cls.__members__)

                self.assertEqual(after, before + 1)
                self.assertIs(cls(value), new)
                self.assertIn(value, cls._value2member_map_)  # type: ignore[attr-defined]


class UnregisteredMemberHelperTests(unittest.TestCase):
    """:meth:`_unregistered_member` in isolation, on every one of tier 1's
    registries -- not only those whose own ``_missing_`` happens to call it.
    It is part of the shared template regardless, so every registry carries
    it whether or not its own ``_missing_`` uses it (the rest keep their
    own bespoke ``process()``-driven ``_missing_``, out of tier 1's scope),
    and this pins that the helper itself behaves identically on all of them.

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
    build a new string, for the shapes this tree's ``name`` arguments
    are ever manufactured from: ``%``-formatting, string concatenation, an
    f-string, ``str.format``, and ``sep.join([...])``. :obj:`None` if
    ``expr`` is not one of those combining shapes *at its own top
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
    varies with the value risks the exact ``__members__`` collision a mint
    risks. Keyed on *which operand is combined*, not on the format
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

    A call's *arguments* need a plainer rule than its receiver does: a bare
    ``value``/``key`` passed as data to ``str(...)``, ``operator.mod(...)``,
    ``.format_map(...)``, or nested inside a
    set/generator/list-comprehension/``map(...)`` argument to
    ``.join(...)``, is not to be cleared the way a receiver is, since an
    argument being the value at all is already how each of those shapes
    glues it to something else. Every argument of any call is therefore walked bluntly for
    ``value``/``key`` regardless of how deeply it is wrapped, while a
    receiver keeps the narrower, recursive check that preserves
    ``value.upper()``'s exemption.

    Known latent gap, deliberately not closed here: ``'x_%s' %
    self._value_`` (or ``cls._value_``) refers to the same datum through
    the enum machinery's own attribute rather than through the
    conventional ``value``/``key`` parameter name, which this function has
    no way to recognise without hardcoding attribute names as well as
    parameter names -- a broader heuristic than the sweep needs. Nothing
    under :mod:`pcapkit.const` writes a ``name`` argument this way.

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
        # (measured: the sweep stayed at 1012/0). It genuinely
        # does over-flag: ``value.upper()`` alone is exempt (it is the
        # receiver case just above), but the exact same expression as an *argument* --
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
    # The manufactured shapes -- each embeds ``value``, the thing being looked up, into the label.
    ('percent-s-value', "cls._unregistered_member(value, 'x_%s' % value)", True),
    ('percent-x-value', "cls._unregistered_member(value, 'x_%x' % value)", True),
    ('concat-str-value', "cls._unregistered_member(value, 'x_' + str(value))", True),
    ('format-method-value', "cls._unregistered_member(value, 'x_{}'.format(value))", True),
    # An f-string embedding value is the same shape as the four above.
    ('fstring-value', "cls._unregistered_member(value, f'x_{value}')", True),
    # A wrapping call around a combining shape -- hoisting a
    # .upper()/.zfill()/str()/.join() outside the %/+/f-string -- must not
    # silently disable the guard.
    ('percent-value-then-upper', "cls._unregistered_member(value, ('x_%s' % value).upper())", True),
    ('percent-value-then-zfill', "cls._unregistered_member(value, ('x_%d' % value).zfill(8))", True),
    ('str-wrapping-percent', "cls._unregistered_member(value, str('x_%s' % value))", True),
    ('fstring-then-upper', "cls._unregistered_member(value, f'x_{value}'.upper())", True),
    ('join-list-with-value', "cls._unregistered_member(value, ''.join(['x_', str(value)]))", True),
    # On the generic call-recursion path, a bare ``ast.Name`` argument (as
    # opposed to the outermost expression) is not exempt the way ``value``
    # alone is at the top level -- that would miss the value being glued in
    # as *data* to a call rather than merely transformed. None of these
    # exists under pcapkit/const/
    # (latent, not live), but the census that found them is exactly
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


#: The one call-chain every hex-suffixed manufactured name shares, on every
#: branch #775 deliberately keeps unrenamed rather than
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
    """Whether ``name_arg`` is *exactly* the one shape #775 preserves
    unrenamed on :class:`~pcapkit.const.reg.ethertype.EtherType`'s
    range branches and :class:`~pcapkit.const.ipx.socket.Socket`'s one --
    a ``%``-format :class:`~ast.BinOp` whose left operand is a string
    constant ending in the literal ``'_0x%s'``, and whose right operand is
    structurally identical (by :func:`ast.dump`, so source-text formatting
    such as whitespace or quote style never matters) to
    :data:`_HEX_SUFFIX_SHAPE`.

    Deliberately narrower than :func:`is_manufactured`'s own
    combining-operand check: it exists only to pick these already-
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
    bare, with no numeric value appended. An attributed vendor block keeps its
    number, because there it is part of the real name (``Motorola_0x8705`` names one
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
    ``%`` (the ``'Unassigned_%d' % value`` mint shape, spelled out as a
    literal), or an equivalent ``%``-formatted :class:`~ast.BinOp` or
    f-string. It therefore covers every call site the #775/#847 ruling and
    #860's step 2 convert: :class:`~pcapkit.const.http.
    status_code.StatusCode`, :class:`~pcapkit.const.ftp.return_code.
    ReturnCode`, :class:`~pcapkit.const.ftp.return_code.ResponseKind`,
    :class:`~pcapkit.const.ftp.return_code.GroupingInformation`,
    :class:`~pcapkit.const.pcapng.option_type.OptionType`,
    :class:`~pcapkit.const.ftp.command.FEATCode`,
    :class:`~pcapkit.const.ftp.command.Command` and
    :class:`~pcapkit.const.http.method.Method` (see
    :data:`BESPOKE_UNMINT_CONVERTED_REGISTRIES` above), plus every
    ``super()._unregistered_member(value, name)`` forwarding call each of
    those ``__new__``-carrying overrides makes internally -- not a
    fresh call site with a label of its own, just relaying whatever the true
    call site already passed, so it is walked and counted here too rather
    than specially excluded -- plus the sites on :class:`OptionType`'s own
    ``get()`` (its int/namespace path and its ``str`` path, both independent
    of ``_missing_``), and the ``_missing_`` branches on
    :class:`~pcapkit.const.reg.apptype.apptype.AppType` itself, the one more
    inside its own ``get()``, and the one ``super()._unregistered_member(...)``
    forward its own override makes; see
    :class:`AppTypeUnmintConvertedTests` below.
    ``'%s_unknown' % namespace`` on the first of those two is deliberately
    *not* flagged as manufactured despite being a ``%``-formatted
    :class:`~ast.BinOp`: unlike ``'Unassigned_%d' % value``, the substituted
    operand is a bounded namespace prefix, not the value being minted, so it
    carries none of the numeric-suffix collision risk the check exists to
    catch -- see :func:`is_manufactured`'s own docstring below.

    The open-vocabulary ones among those are a genuinely different shape from
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
    (including :class:`~pcapkit.const.reg.apptype.apptype.AppType`'s own)
    -- is out of scope and untouched by this sweep entirely,
    since it never calls ``_unregistered_member`` in the first place; minting
    there is the explicit, caller-named path the sweep is not about.

    GitHub issue #775 converts the attributed branches too -- every one of
    :class:`~pcapkit.const.reg.ethertype.EtherType`'s and
    :class:`~pcapkit.const.ipx.socket.Socket`'s one -- and deliberately keeps
    each one's hex-suffixed name unchanged (PR #878 scoped it this way:
    keeping the existing hex-suffixed name, since the conversion is about not
    registering rather than renaming). That is the exact manufactured,
    value-suffixed shape :func:`is_manufactured` exists to flag -- unlike
    ``'%s_unknown' % namespace`` above, the substituted operand here really is
    ``value``, via ``hex(value)[2:].upper().zfill(4)``. Flagging it anyway
    would be a false positive in the sense that matters: the collision this
    check protects against is two *minted* members sharing a name at different
    values, and none of these calls ever mints, so nothing can collide
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

        # Sanity: the sweep itself must actually be exercising something.
        # The floor is the call-site total of the #775/#847 and #860
        # conversions -- true call sites, each override's own ``super()``
        # forward, OptionType.get()'s own paths, AppType's, and EtherType's
        # and Socket's -- so a walk that silently stops finding sites fails.
        self.assertGreaterEqual(call_count, 1065,
                                 f'expected at least 1065 _unregistered_member call sites, found {call_count}')
        # And that the exemption is actually earning its keep, rather than a
        # dead carve-out nothing reaches: one per EtherType range
        # branch, plus Socket's one.
        self.assertEqual(exempt_hits, 53,
                          f'expected exactly 53 hex-suffixed-name exemptions to fire, found {exempt_hits}')
        self.assertEqual(offenders, [],
                          'found _unregistered_member call(s) with a manufactured name:\n'
                          + '\n'.join(offenders))


class RulingConversionDoesNotMintTests(unittest.TestCase):
    """Tier 2's #775/#847 ruling, behaviourally: a value whose label is a
    bare status word must come back as a throwaway pseudo-member, not a mint,
    the same regression :class:`UnassignedRangeDoesNotMintTests` above proves
    for tier 1's registries. Swept across :data:`RULING_CONVERTED_WITH_REACHABLE_GAP`
    -- the converted registries whose branch a real lookup can
    actually reach; the rest are proved by source instead, in
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


#: Registries whose ``_missing_`` legitimately mints on some branches (real
#: attributed names), so the blanket "no extend_enum left" sweep below does
#: not apply to them. Empty: every branch on
#: :class:`~pcapkit.const.reg.ethertype.EtherType` and
#: :class:`~pcapkit.const.ipx.socket.Socket` converts, attributed ones
#: included (#775). Kept as an empty-by-construction frozenset so the two subtractions below
#: stay self-documenting about *why* nothing is excluded, and so a future
#: registry that becomes genuinely mixed has a named place to be added.
#: :class:`EtherTypeMixedMintTests` and :class:`IPXSocketMixedMintTests` prove
#: their attributed-vendor probes do not mint, alongside the unassigned rows.
_MIXED_REGISTRIES = frozenset()  # type: frozenset[tuple[str, str]]


class RulingConversionSourceTests(unittest.TestCase):
    """Source-level proof for those of :data:`RULING_CONVERTED_REGISTRIES`
    with no reachable gap (every in-bounds value already names a real member,
    so no lookup can exercise the branch)
    -- and, as a completeness check, for the wholly-converted registries:
    none of their ``_missing_`` bodies may call :func:`~aenum.extend_enum`.
    :data:`_MIXED_REGISTRIES` is empty, so nothing is excluded here -- see
    its own comment."""

    def test_no_reachable_gap_registries_no_longer_call_extend_enum(self) -> None:
        # EtherType belongs to RULING_CONVERTED_WITH_REACHABLE_GAP: its Old
        # Xerox branch is not shadowed by the wider IEEE802.3 range (GitHub
        # issue #862), so its first converted branch by source order is
        # directly probeable like any other reachable-gap registry. The
        # `_MIXED_REGISTRIES` subtraction below is a defensive no-op -- neither
        # mixed registry needs removing from `RCR - RG` (EtherType is already
        # in RG; Socket never appeared in RULING_CONVERTED_REGISTRIES to begin
        # with)
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
        """EtherType and Socket carry no ``extend_enum`` call either (#775),
        the same invariant
        :meth:`test_every_wholly_converted_registry_no_longer_calls_extend_enum`
        proves for the rest -- named separately because Socket is not a
        member of :data:`RULING_CONVERTED_REGISTRIES`, so the loop above alone
        would never reach it."""
        from pcapkit.const.ipx.socket import Socket
        from pcapkit.const.reg.ethertype import EtherType

        for cls in (EtherType, Socket):
            with self.subTest(registry=cls.__qualname__):
                source = inspect.getsource(cls._missing_)  # type: ignore[attr-defined]
                self.assertNotIn('extend_enum', source)
                self.assertIn('_unregistered_member', source)


class EtherTypeMixedMintTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.ethertype.EtherType`'s unassigned rows and
    attributed vendor blocks. The #775/#847 ruling converts ``DEC
    Unassigned`` and the "Old Xerox Experimental..." row, and #775 converts
    every attributed vendor block (a real company's own name for its own
    code) too, so no branch mints -- ``EtherType(0x0888)`` resolves to an
    unregistered ``Xyplex_0x0888``. :meth:`test_formerly_attributed_vendor_block_
    no_longer_mints` below pins that one named probe (``Xyplex``)."""

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

    def test_formerly_attributed_vendor_block_no_longer_mints(self) -> None:
        """``Xyplex`` (0x0888), a real attributed name, does not mint (#775):
        it resolves to an unregistered member with the hex-suffixed name
        exactly as the crawler renders it -- PR #878 scoped it this way:
        keeping the existing hex-suffixed name, since the conversion is about
        not registering rather than renaming. Same shape as
        :meth:`test_unassigned_rows_do_not_mint` above."""
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
    """:class:`~pcapkit.const.ipx.socket.Socket`'s unassigned rows and its
    attributed one. The #775/#847 ruling converts ``Experimental`` and the
    dynamically/statically assigned labels, and #775 converts ``Registered
    by Xerox``, the company one, too, so ``Socket(0x0010)`` resolves to an
    unregistered ``Registered by Xerox_0x0010``; see
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
        """``Registered by Xerox`` (0x0010), the company name, does not mint
        (#775): it resolves to an unregistered member with the hex-suffixed
        name exactly as the crawler renders it -- same ruling, same reasoning
        as
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


#: The range-bounded ones of #860's bespoke classes step 2's PR 1 brought onto
#: :class:`~pcapkit.corekit.enum.EnumRegistry` and converted: (module, class
#: name, a probe value inside the converted range, the bare label the
#: conversion uses). Every one of these has a custom ``__new__`` with
#: extra per-member attributes, unlike any of the tier-2 registries in
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
    """GitHub issue #860 step 2, PR 1: the range-bounded bespoke, non-
    :class:`~pcapkit.corekit.enum.EnumRegistry` classes brought onto the base
    and converted. Unlike every registry above, each of these carries a
    custom ``__new__`` setting extra attributes (``message``;
    ``description``/``kind``/``group``; ``opt_name``/``opt_value``), so the
    base's generic :meth:`~pcapkit.corekit.enum.EnumRegistry.
    _unregistered_member` -- which calls the member type's ``__new__``
    directly and sets only ``_name_``/``_value_`` -- would leave those
    attributes unset and make ``str()``/``repr()`` raise on the result. Each
    class therefore overrides :meth:`_unregistered_member` to reconstruct
    them the same way ``__new__`` would. These tests exercise that
    reconstruction directly, not just that lookup does not mint.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_unassigned_value_resolves_without_minting(self) -> None:
        """Swept across every one of them: resolves, does not mint, repeated lookup is
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
        """Every one of :meth:`~pcapkit.const.http.status_code.StatusCode.
        _missing_`'s ``if`` branches, not just the first -- each is its own
        source line and its own converted call, so covering only one leaves
        the rest untested."""
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
        so a future edit that adds one notices it is changing something the
        base provides for free."""
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
        A mint *does* add to ``__members_ns__``, every time, so this is pinned
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
        """Guards against :meth:`OptionType.get` minting directly on a miss
        (bypassing ``_missing_`` entirely) -- a second, independent mint
        site, on the wire-facing path
        (:meth:`pcapkit.protocols.misc.pcapng.PCAPNG._make_pcapng_options`
        calls ``get()`` with raw option-code bytes). The owner's ruling names
        ``get`` explicitly -- the same reason
        :class:`~pcapkit.const.ftp.command.Command`/:class:`~pcapkit.const.
        http.method.Method`'s own ``get()`` mint sites convert. Leaving this
        one minting while ``_missing_`` does not would be the exact
        contradiction that conversion is for."""
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
        """The subtler of the two: guards against ``get()``'s ``str``-keyed
        branch minting ``key`` itself as the member's *name*, with
        ``default`` as its value -- the same "no information to register one
        properly" reasoning as the int path, just with the roles of ``key``
        and ``default`` swapped in the ``extend_enum`` call."""
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
    """The open-vocabulary ``StrEnum`` classes -- unlike every other unmint
    branch above or of tier 2, a miss here would not mint a synthetic
    numeric placeholder under a procedural label (``Unassigned_%d``,
    ``Unknown_%d``); it would mint the literal, exact string it was asked to
    resolve, as its own name. That reads as a case for minting (the label is
    not manufactured), but GitHub issue #860 settles it the other way: ``get()`` does not mint,
    because only ``register()`` creates a new registry entry, and for these
    registries only IANA-registered values are legitimate -- ``get()``
    simply does not have enough information to build a new one. Concretely:
    :class:`~pcapkit.const.ftp.command.Command` needs ``feat``/``desc``/``type``/``conf`` and
    :class:`~pcapkit.const.http.method.Method` needs
    ``safe``/``idempotent``, neither of which a bare wire string carries, so
    minting would register a permanently hollowed-out member for each.
    :class:`~pcapkit.const.ftp.command.FEATCode` has no custom ``__new__``
    at all and needs no override.

    Both ``_missing_`` and each class's own ``get()`` (a *second*,
    independent mint site bypassing ``_missing_`` entirely, the same shape
    as :class:`~pcapkit.const.pcapng.option_type.OptionType`'s) refuse to
    mint, since the owner's reasoning names ``get`` explicitly and
    leaving it minting while ``_missing_`` does not would be a direct
    contradiction. ``Command``/``Method``'s ``_unregistered_member``
    override canonicalises the member's *name* to upper case and keeps the
    caller's own casing as its value, so ``get('frob')`` and ``get('FROB')``
    are unequal, and a repeated ``get('frob')`` is equal but, with nothing
    cached, never *identical* -- see the production regression test,
    ``tests/protocols/application/test_ftp_unit.py::FTPUnitTests::test_command_get_is_case_insensitive``,
    which pins exactly that with ``assertEqual``, ``assertIsNot`` and
    ``assertNotEqual``. Its HTTP counterpart is
    ``tests/protocols/application/test_http_unit.py::HTTPUnitTests::test_method_get_is_now_case_sensitive``
    (#896).

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_featcode_import_mints_nothing(self) -> None:
        """The guard against the import-time mutation coming back -- count-
        agnostic on purpose.

        Without the fix, importing :mod:`pcapkit.const.ftp.command` mints
        :class:`~pcapkit.const.ftp.command.FEATCode` members as a side
        effect of evaluating :class:`~pcapkit.const.ftp.command.Command`'s
        own class body -- each row referencing an upper-case ``FEAT code``
        calls ``FEATCode('AUTH')`` etc., and :meth:`FEATCode._missing_`
        mints one the first time. The generator declares every ``FEAT
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
        time would build."""
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
        """The convention pinned across every open-vocabulary class:
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
        holds), matching what a mint does for this class -- only the *name*
        is canonicalised. Swapping the value for the canonicalised name would
        make ``Command('xyzw') == 'xyzw'`` false, a real behaviour break for
        any caller comparing a member with its wire string."""
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
        casing is a genuinely different value and correctly not equal. A
        minting lookup caches instead, returning the identical,
        first-seen-casing object for both calls; not caching is #860's one
        observable difference here, not a casing change."""
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
        content. The *unregistered* path bypasses ``__new__`` entirely, so it
        is independent of GitHub issue #870's fix to :meth:`Method.__new__`
        (``str.__new__(cls, value)``, mirroring
        :class:`~pcapkit.const.ftp.command.Command`'s own ``__new__``), which
        gives a *registered* member its value as its :class:`str` payload too
        -- see :mod:`tests.const.test_const_str_payload_870_unit` for the
        direct pin of that fix, registry-wide."""
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
        (``'GET'``), not the lower-cased ``'get'``: ``Command``'s FTP command
        codes stay case-insensitive per :rfc:`959#section-5`, but the HTTP
        method token :rfc:`9110#section-9.1` covers is case-sensitive
        (GitHub issue #896), so ``Method.get('get')`` does not resolve to
        :attr:`Method.GET` --
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
    :class:`~pcapkit.const.ftp.return_code.ReturnCode` are the converted
    classes that use the base's :meth:`~pcapkit.corekit.enum.EnumRegistry.get`
    -- which uses :data:`~pcapkit.corekit.sentinels.NO_DEFAULT` and never
    mints while resolving ``default`` (#864) -- rather than a hand-written
    ``get()`` on the ``default == -1`` convention #857/#859 retired.

    Measured when the hand-written form was replaced, so that no caller in
    :mod:`pcapkit` or :mod:`tests` depends on it: ``grep`` found exactly one
    production call site each (:mod:`pcapkit.protocols.application.httpv1`
    and :mod:`pcapkit.protocols.application.ftp`), neither passing a
    ``default`` or a ``str`` key -- both call ``get(<int>)`` with no default,
    which raises identically either way on an unresolvable key. The
    hand-written ``str``-key branch (look up-or-mint *by name*, keyed on
    ``default``) had no caller anywhere in the tree; the base's ``str``-key
    path does an ordinary name-then-value lookup instead and never mints.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_statuscode_get_omitted_default_still_raises(self) -> None:
        """The one production call site's shape: no default passed, so an
        unresolvable key must raise -- true under both the ``default == -1``
        convention and the ``NO_DEFAULT`` one."""
        from pcapkit.const.http.status_code import StatusCode

        with self.assertRaises(ValueError):
            StatusCode.get(9999)

    def test_statuscode_get_minus_one_is_now_an_ordinary_default(self) -> None:
        """``-1`` is not the sentinel for *no default* (it is under the
        retired ``default == -1`` convention); it is just an :class:`int`
        that -- like any other -- is only honoured if it already names a
        registered member. ``-1`` does not, on this registry, so passing it
        explicitly raises the *original* key's error rather than a re-raise
        for matching a sentinel."""
        from pcapkit.const.http.status_code import StatusCode

        with self.assertRaises(ValueError) as caught:
            StatusCode.get(9999, -1)
        self.assertIn('9999', str(caught.exception))

    def test_statuscode_get_default_never_mints(self) -> None:
        """#864's ruling, on this registry: a ``default`` landing inside a
        converted unassigned range does not resolve to
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

    :class:`Method` does not resolve that way: it is case-sensitive (GitHub
    issue #896, over #583's case-insensitive lookup), since RFC 9110 Section
    9.1 makes the HTTP method token case-sensitive, unlike FTP's command codes
    (RFC 959 Section 5.3), so ``Method.get('Get')`` does not return :attr:`Method.GET`
    -- see ``test_method_get_is_now_case_sensitive`` below. ``Method`` keeps
    its own ``get()`` rather than the base's, because it needs to build an
    unregistered member preserving the caller's own casing on a miss (the
    base's generic ``get()`` only ever raises or falls back to an
    already-registered ``default`` for a ``str`` key, per
    :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own docstring) -- #896
    concerns only whether the lookup that precedes that fallback is
    case-sensitive.

    :class:`OptionType`'s ``get()`` does its own multi-namespace dispatch via
    :attr:`__members_ns__` with no base equivalent at all. These are
    regression guards, not new coverage.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_method_get_is_now_case_sensitive(self) -> None:
        """GitHub issue #896: only the exact registered casing resolves.

        RFC 9110 Section 9.1 makes the method token case-sensitive, so a
        differently-cased probe such as ``Method.get('Get')`` builds its own
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

    Largest of the bespoke classes #860 step 2 converts: an AST walk over
    :meth:`AppType._missing_` finds range-bounded branches
    -- placeholders (``unassigned_<port>`` and ``reserved_<port>``), and
    branches naming a real service IANA assigns to a whole span rather than
    to one declared member each (``x11`` for TCP and again for UDP,
    ``active-net``, ``satvid-datalnk``, ``vrml-multi-use``, ``ircu``, ``swx``,
    ``flex-lm``) -- plus one more, independent mint site inside
    :meth:`AppType.get` itself (``PORT_<port>_<transport>``, labelled
    ``'unknown'``, for a port neither
    ``_missing_``'s ranges nor the registry's own declared members cover).

    A deliberate scope decision, stated here because a reviewer could
    reasonably expect the ``FEATCode`` precedent instead: the real-name
    spans above convert to :meth:`~pcapkit.corekit.enum.
    EnumRegistry._unregistered_member` exactly like the placeholder spans,
    *not* declared as real, individually-listed members the way #860 step 2's
    PR 1 declared ``FEATCode``'s members. ``FEATCode``'s fix addressed a
    *different* defect -- a const module minting members as a side effect of
    merely being imported, which does not exist here, since every one of
    these spans mints only on an actual port lookup -- and the owner's
    ruling for the whole ``AppType`` family draws no distinction between a
    real name and a placeholder: GitHub issue #860 settled that ``get()``
    must not mint regardless of whether the value it would construct is a
    genuine IANA-registered name or a manufactured placeholder, because
    only ``register()`` may create a new entry and ``get()`` never has
    enough information to build one itself. A lookup resolving
    ``TCP(6010)`` therefore returns an *unregistered* ``x11``
    member -- correct as a service name, but absent from
    ``__members__``/``_value2member_map_`` until someone calls
    ``TCP.register(6010, 'x11')`` explicitly.

    Unlike every bespoke class #860 step 2's PR 1 converted,
    :meth:`AppType.get` does genuine transport-protocol dispatch through
    :meth:`~AppType._dispatch` -- so, unlike
    :class:`~pcapkit.const.http.status_code.StatusCode`/
    :class:`~pcapkit.const.ftp.return_code.ReturnCode`, it keeps its own
    ``get()`` rather than being replaced by the base's; and, unlike
    :class:`~pcapkit.const.ftp.command.Command`/
    :class:`~pcapkit.const.http.method.Method`/
    :class:`~pcapkit.const.pcapng.option_type.OptionType`, its own
    ``_unregistered_member`` override reconstructs three attributes (``svc``,
    ``port``, ``proto``) rather than one or two, because
    :meth:`AppType.__new__` sets all three and none is optional for
    :meth:`__repr__`/:meth:`__str__`/:meth:`__int__`/the comparison
    operators/:attr:`~AppType.aliases` to run on the result without raising.

    :meth:`AppType.register` comes from #874. The base's generic one (which
    calls ``cls.__new__(cls, value)`` with only ``value``) would build a
    member with ``svc='<null>'`` and ``proto=TransportProtocol.undefined``,
    silently wrong, if this class mixed in
    :class:`~pcapkit.corekit.enum.EnumRegistry` without an override. Scoped
    like :meth:`~AppType.register_alias` to **this** per-transport registry
    rather than dispatched through :meth:`~AppType._dispatch`, for the same
    reason register_alias is: minting on one transport must never
    leak onto a transport IANA never assigned the service to.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_apptype_family_carries_the_registry_protocol(self) -> None:
        """#842's ruling is that ``get``/``get_all``/``register``/
        ``register_alias`` exist on every registry -- #860 step 2 PR 2 is
        what actually delivers that for this family, including ``register``
        (#874)."""
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
        Every ``if``/``cls.__transport__ is ...`` test has the same shape
        whether its branch ends in ``extend_enum(...)`` or
        ``_unregistered_member(...)`` -- this pins the dispatch, not just
        that nothing mints."""
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
        ``_missing_``'s ranges either, so it reaches :meth:`AppType.
        get`'s own, second, independent mint site --
        distinct from the one inside ``_missing_``, and easy to miss when
        converting only the latter (the same second mint site
        :class:`~pcapkit.const.pcapng.option_type.OptionType`'s own ``get()``
        carries)."""
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
        """The asymmetry #874 leaves in place, deliberately: a direct
        ``TCP(54321)`` has no ``get()`` around it to catch ``_missing_``'s
        :obj:`None` answer and build an ``'unknown'`` member from it, so it
        raises -- only :meth:`AppType.get` has the fallback, the constructor
        keeping its own behaviour of raising rather than minting for a value
        inside
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
        registered member is reached at all (verified directly: ``TCP(80)``
        raises for the real, declared ``http`` member too). ``TCP.get(port)``
        and the ``__registry__`` side table are the two things a real
        ``register()`` call is checked against below."""
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
        """:meth:`AppType.register`/:meth:`AppType.register_alias` share
        :meth:`AppType._sanitize_identifier` rather than each carrying its
        own copy of the sanitising steps -- this checks the alias path
        through it."""
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
        -- is refused by :meth:`AppType._dispatch`, as #874 leaves it.
        (Deliberately not a composite like ``tcp | udp``: under ``auto()``
        that equals ``sctp`` numerically and dispatches there rather than
        raising, which is the one accepted, explicitly untested consequence
        of the ``auto()`` numbering -- see
        :class:`TransportProtocolAutoTests`.)"""
        from pcapkit.const.reg.apptype.apptype import AppType

        with self.assertRaises(ValueError):
            AppType.get(80, proto=99)


class TransportProtocolAutoTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`'s
    ``auto()`` numbering, from #860 step 2 PR 2. The owner ruled on #860
    that, since ``|`` composition is not allowed, ``auto()`` in place of
    power-of-two spacing is the right move -- a breaking change, but an
    accepted one. On the one behavioural consequence -- a hand-composed
    ``tcp | udp`` equalling ``sctp`` numerically (``1 | 2 == 3``) rather than
    naming no member and being refused as a whole -- the same thread settled
    that no test should pin it: the path is obsolete after the breaking
    change, and a test would preserve it as though it still mattered. So this
    class deliberately covers only the values and the stale comment's
    absence, not the composition consequence: no test here
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
        """``TransportProtocol`` does not mint through
        :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`, and
        does not mix in :class:`~pcapkit.corekit.enum.EnumRegistry` -- only
        ``AppType`` and its transport subclasses do."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol
        from pcapkit.corekit.enum import EnumRegistry

        self.assertFalse(issubclass(TransportProtocol, EnumRegistry))

    def test_get_still_refuses_an_unrecognised_name(self) -> None:
        """GitHub PR #836's ruling against extending ``TransportProtocol``
        at all holds under the ``auto()`` numbering -- :meth:`~pcapkit.const.
        reg.apptype.apptype.TransportProtocol.get` has no ``_missing_`` of its
        own and refuses outright rather than minting.

        :exc:`KeyError`-shaped: the override does no ``KeyError`` ->
        ``ValueError`` conversion (GitHub issue #923); the refusal itself is
        what this test is about."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        with self.assertRaises(KeyError):
            TransportProtocol.get('not-a-real-transport')

    def test_stale_power_of_two_comment_is_gone(self) -> None:
        """Per GitHub issue #860: an in-code comment claiming the values
        "must keep" power-of-two spacing contradicts the PR #836 ruling that
        nothing composes a ``TransportProtocol``, so the generated source
        carries none -- checked against the generated source itself, not the
        docstring here, so a regeneration that reintroduces it fails this
        test."""
        import pcapkit.const.reg.apptype.apptype as apptype_module

        source = pathlib.Path(apptype_module.__file__).read_text(encoding='utf-8')
        self.assertNotIn('must keep', source)
        self.assertNotIn('the power-of-two spacing the values', source)


if __name__ == '__main__':
    unittest.main()
