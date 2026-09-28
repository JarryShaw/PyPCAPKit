# -*- coding: utf-8 -*-
"""Regression tests for GitHub issue #775's tier 1: the miss path must not mint.

The maintainer's ruling on #775, verbatim: *"so that we dont create registered
enums out of unrecognised/unregistered values, unless user/caller explicitly
created them"* -- and lookup never counts as asking for a name, only the new
:meth:`register` classmethod does. Before this change, both ``get()``'s string
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
something worth keeping. That is tier 2, decided on #775 and carried out on
#847: the owner's ruling, verbatim, is *"a final concrete assigned name ->
mint; a notation for the readers -> unmint"*. Applied registry by registry to
every ``_missing_`` that still called :func:`~aenum.extend_enum` -- measured
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

from tests._support import ISOLATED_PREFIXES, purge_modules, restore_modules, snapshot_modules

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
#: :class:`~pcapkit.const.ipx.socket.Socket` (also mixed) already demonstrates
#: in this list below. EtherType has therefore joined this set; see
#: :data:`ETHERTYPE_UNASSIGNED_PROBES`'s comment for the probe itself, still
#: covered explicitly by :class:`EtherTypeMixedMintTests` as well since it
#: remains a mixed registry.
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
#: ruling: ``DEC Unassigned`` and the historical list's own "Old Xerox
#: Experimental values. Invalid as an Ethertype since 1983." both convert,
#: because the label itself says nothing was assigned. Every *other* named
#: block -- companies the historical list attributes a real code range to --
#: stays a mint; :data:`ETHERTYPE_KEPT_PROBE` pins one (``Xyplex``) as a
#: regression guard.
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
ETHERTYPE_KEPT_PROBE = (0x0888, 'Xyplex_0x0888')

#: :class:`~pcapkit.const.ipx.socket.Socket` probes for the owner's ruling:
#: ``Experimental`` and the three "who may claim this pool" policy labels
#: convert; ``Registered by Xerox`` -- a real ownership fact, not a status
#: word -- keeps minting, pinned by :data:`IPX_SOCKET_KEPT_PROBE`.
IPX_SOCKET_UNASSIGNED_PROBES = {
    0x0025: 'Experimental',
    0x4001: 'Dynamically Assigned Socket Numbers',
    0x8001: 'Statically Assigned Socket Numbers',
    0x0BBA: 'Dynamically Assigned',
}
IPX_SOCKET_KEPT_PROBE = (0x0010, 'Registered by Xerox_0x0010')


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
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

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
        """The fallback is itself a value lookup, so a default landing in a
        bounded-unassigned range returns the same kind of pseudo-member the
        int path does -- rather than minting a member literally named after
        the caller's unresolved key, which is what this used to do."""
        from pcapkit.const.arp.hardware import Hardware

        before = len(Hardware.__members__)
        result = Hardware.get('Definitely-Not-A-Member', 40)
        self.assertEqual(result.value, 40)
        self.assertEqual(before, len(Hardware.__members__))
        self.assertNotIn('Definitely-Not-A-Member', Hardware.__members__)


class RegisterStillMintsTests(unittest.TestCase):
    """The one caller-named, explicit path must still grow the registry."""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

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
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

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


class UnregisteredMemberNameIsBareTests(unittest.TestCase):
    """#775's Q1 follow-up, the maintainer's ruling verbatim: *"Q1 - bare it
    is."* Asked whether the non-minting path should honour the registry's
    own ``unassigned``/``reserved`` name directly or keep appending the
    numeric value, he chose the bare name -- safe precisely because a
    pseudo-member built by :meth:`_unregistered_member` never enters
    ``__members__``/``_member_map_``/``_value2member_map_``, so two
    same-named pseudo-members (e.g. ``Chunk._unregistered_member(20,
    'Unassigned')`` and ``(70, 'Unassigned')``) cannot collide the way two
    *minted* ``extend_enum`` members with the same name would.

    This walks every generated :mod:`pcapkit.const` module by AST -- rather
    than pinning one example -- and asserts that every
    ``cls._unregistered_member(...)`` call site passes a plain string
    literal with no ``%`` formatting. It therefore covers all 49 call sites
    tier 1's follow-up touched, plus the 172 tier 2's #775/#847 ruling added
    (221 total, measured on this tree -- see :data:`RULING_CONVERTED_
    REGISTRIES` above), and any added by a later regeneration, without caring
    which registry they belong to. A call site still using ``extend_enum(...)``
    -- the 9 classes across 6 files tier 2 left untouched because they are not
    :class:`~pcapkit.corekit.enum.EnumRegistry` yet (:class:`~pcapkit.const.
    reg.apptype.apptype.AppType` and friends, see the module docstring), plus
    the handful of still-minting branches on :class:`~pcapkit.const.reg.
    ethertype.EtherType` and :class:`~pcapkit.const.ipx.socket.Socket` that the
    ruling kept, plus :class:`~pcapkit.const.mh.cga_type.CGAType` -- is out of
    scope and untouched by this sweep, since a minted name still needs its
    numeric suffix to avoid a genuine ``__members__`` collision.

    (Corrected from an earlier draft of this docstring, which estimated
    "~92 registries still mint" and named ``pcapkit.const.mh`` and
    ``BlockType`` as examples -- both were converted by tier 2 and no longer
    apply; the AST walk in the module docstring above measured the real
    figure at 89.)

    """

    def test_every_unregistered_member_call_passes_a_bare_name(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        const_root = repo_root / 'pcapkit' / 'const'
        self.assertTrue(const_root.is_dir(), f'{const_root} is not a directory')

        offenders = []  # type: list[str]
        call_count = 0

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
                is_bare_literal = (
                    isinstance(name_arg, ast.Constant)
                    and isinstance(name_arg.value, str)
                    and '%' not in name_arg.value
                )
                if not is_bare_literal:
                    segment = ast.get_source_segment(source, node)
                    offenders.append(f'{path.relative_to(repo_root)}:{node.lineno}: {segment}')

        # Sanity: the sweep itself must actually be exercising something --
        # tier 1's follow-up touched exactly 49 call sites across 21 files,
        # and tier 2's #775/#847 ruling added 172 more across 82 files, for
        # 221 total measured on this tree.
        self.assertGreaterEqual(call_count, 221,
                                 f'expected at least 221 _unregistered_member call sites, found {call_count}')
        self.assertEqual(offenders, [],
                          'found _unregistered_member call(s) with a non-bare name:\n' + '\n'.join(offenders))


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
#: ipx.socket.Socket` are the two *mixed* registries: most of their
#: ``_missing_`` legitimately keeps minting (real attributed names), so the
#: blanket "no extend_enum left" sweep below does not apply to them --
#: :class:`EtherTypeMixedMintTests` and :class:`IPXSocketMixedMintTests` cover
#: their converted rows specifically instead.
_MIXED_REGISTRIES = frozenset({('pcapkit.const.reg.ethertype', 'EtherType'), ('pcapkit.const.ipx.socket', 'Socket')})


class RulingConversionSourceTests(unittest.TestCase):
    """Source-level proof for the 13 of :data:`RULING_CONVERTED_REGISTRIES`
    with no reachable gap (every in-bounds value already names a real member,
    so no lookup can exercise the branch either before or after this change)
    -- and, as a completeness check, for the 80 wholly-converted registries:
    none of their ``_missing_`` bodies may call :func:`~aenum.extend_enum`
    any more. Excludes the two mixed registries -- see :data:`_MIXED_
    REGISTRIES` -- which keep some ``extend_enum`` calls by design."""

    def test_no_reachable_gap_registries_no_longer_call_extend_enum(self) -> None:
        # EtherType now belongs to RULING_CONVERTED_WITH_REACHABLE_GAP: its
        # masked-branch exclusion (Old Xerox shadowed by the wider IEEE802.3
        # range) was fixed by GitHub issue #862/#865, and its first converted
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


class EtherTypeMixedMintTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.ethertype.EtherType` is the ruling's mixed
    case: ``DEC Unassigned`` and the "Old Xerox Experimental..." row convert,
    every other attributed vendor block (a real company's own name for its
    own code) keeps minting."""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

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

    def test_attributed_vendor_block_still_mints(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        value, name = ETHERTYPE_KEPT_PROBE
        self.assertNotIn(value, EtherType._value2member_map_)  # type: ignore[attr-defined]
        before = len(EtherType.__members__)

        member = EtherType(value)

        self.assertEqual(member.value, value)
        self.assertEqual(member.name, name)
        self.assertEqual(before + 1, len(EtherType.__members__))
        self.assertIn(value, EtherType._value2member_map_)  # type: ignore[attr-defined]
        self.assertIs(EtherType(value), member)


class IPXSocketMixedMintTests(unittest.TestCase):
    """:class:`~pcapkit.const.ipx.socket.Socket` is the ruling's other mixed
    case: ``Experimental`` and the three "who may claim this pool" allocation-
    policy labels convert; ``Registered by Xerox`` -- a real ownership fact --
    keeps minting."""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

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

    def test_registered_by_xerox_still_mints(self) -> None:
        from pcapkit.const.ipx.socket import Socket

        value, name = IPX_SOCKET_KEPT_PROBE
        self.assertNotIn(value, Socket._value2member_map_)  # type: ignore[attr-defined]
        before = len(Socket.__members__)

        member = Socket(value)

        self.assertEqual(member.value, value)
        self.assertEqual(member.name, name)
        self.assertEqual(before + 1, len(Socket.__members__))
        self.assertIn(value, Socket._value2member_map_)  # type: ignore[attr-defined]
        self.assertIs(Socket(value), member)


if __name__ == '__main__':
    unittest.main()
