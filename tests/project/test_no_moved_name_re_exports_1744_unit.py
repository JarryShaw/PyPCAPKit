# -*- coding: utf-8 -*-
"""A moved name keeps no re-export at its old path (GitHub issue #1744).

The owner ruled on #1715 and #1103 that a moved name or module keeps no
re-export at its old path, ``TLSKeyLabel`` included. Under ruling D1 on #1744
only an *explicit* re-export goes: an alias assignment, a name in a non-home
module's ``__all__``, or a name documented as importable there. A module that still uses a name it imports from
the new home keeps the import, so the old path resolving through it is expected.

The protocol packages' ``Schema_*`` and ``Data_*`` names are the exception the
owner ruled in review of #2753: a package binds each public class its ``schema``
and ``data`` modules define under them, outside ``__all__``, as 1.5.1's aggregators
exposed those classes; :mod:`tests.protocols.test_protocol_packages_2534_unit`
pins them.

These checks pin that:

* :class:`TestNotExported` -- no removed name is in its old module's
  ``__all__``;
* :class:`TestNotBound` -- a name the old module only re-exported is not bound
  there at all, and a name it still uses is the new home's own object;
* :class:`TestNoReader` -- nothing under :mod:`pcapkit`, ``examples``,
  ``util`` or ``tests`` imports a removed name from its old path, or reads it
  as an attribute of the old module imported whole;
* :class:`TestNotDocumented` -- no ``auto*`` directive under ``docs/`` documents
  a removed name at its old path;
* :class:`TestNoReExportProse` -- no docstring under :mod:`pcapkit` and no page
  under ``docs/`` says a removed name is importable, re-exported or available
  at its old path;
* :class:`TestVersionRemoved` -- the paths that shipped in a release carry
  ``versionremoved`` for the version that removed them, in the module docstring
  and on the docs page, per #1103; the beta-only ones are deleted with no
  directive.
* :class:`TestMovedModules` -- a shipped module that moved whole does not import
  at its old path, and the module that took its place records ``versionremoved``
  for that path, in the docstring and on the docs page.
* :class:`TestShippedNames` -- every name the latest release shipped under
  :mod:`pcapkit.protocols` resolves at its old path, or a ``versionremoved``
  names that path, or names its module where the module went whole or only
  re-exported the name (#2534). The names are read from the release tag by
  :file:`util/shipped_names.py` into a checked-in fixture, as CI has no tags.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import importlib
import inspect
import json
import pathlib
import re
import unittest

from util import shipped_names

#: Test tier (#1958): checks that each moved name's old path is gone, a question about
#: the tree.
__tier__ = 'LATEST'

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Removed paths the old module does not bind at all, as ``(old module, name)``.
PURE = (
    ('pcapkit.protocols.misc.pcapng.protocol', 'TLSKeyLabel'),
    ('pcapkit.corekit.fields.field', 'NoValueType'),
    ('pcapkit.corekit.enum', 'NoDefaultType'),
    ('pcapkit.corekit.module', 'NullType'),
    ('pcapkit.corekit.module', '_get_null'),
    ('pcapkit.protocols.protocol', 'AbsentType'),
    ('pcapkit.foundation.reassembly.data', 'DeferredPacket'),
    ('pcapkit.foundation.traceflow.data', 'DeferredPacket'),
    ('pcapkit.protocols.application.ftp.protocol', 'FTP_DATA'),
    ('pcapkit.protocols.application.rarp.protocol', 'DRARP'),
    ('pcapkit.protocols.application.ngap.protocol', 'ProcedureCode'),
    ('pcapkit.protocols.application.ngap.protocol', 'ProtocolIE'),
    ('pcapkit.protocols.internet.mh.protocol', 'NTPTimestamp'),
    ('pcapkit.protocols.internet.mh.protocol', 'PMIPv6Timestamp'),
    ('pcapkit.protocols.link.arp.protocol', 'InARP'),
    # #2529: renamed after their modules.
    ('pcapkit.protocols.application.httpv1.protocol', 'HTTP'),
    ('pcapkit.protocols.application.httpv2.protocol', 'HTTP'),
    ('pcapkit.protocols.application.httpv1.schema', 'HTTP'),
    ('pcapkit.protocols.application.httpv2.schema', 'HTTP'),
    ('pcapkit.protocols.application.httpv1.data', 'HTTP'),
    ('pcapkit.protocols.application.httpv2.data', 'HTTP'),
    # #2674: helpers called from outside the schema layer, moved to
    # pcapkit.corekit.schema.
    ('pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
    ('pcapkit.protocols.schema', 'keep_short_read'),
    ('pcapkit.protocols.schema', 'replay_short_read'),
    # #2883: format constants read beyond their own protocol, moved to
    # pcapkit.corekit.const.
    ('pcapkit.protocols.misc.pcap.header.schema', 'RESOLUTION'),
    ('pcapkit.protocols.misc.pcap.header.schema', 'RESOLUTION_PLACES'),
    ('pcapkit.protocols.misc.pcapng.schema', 'DEFAULT_RESOLUTION'),
    ('pcapkit.protocols.internet.ipv6.protocol', 'IPV6_NEXT_HEADER_OFFSET'),
    ('pcapkit.protocols.transport.tcp.schema', 'TCP_DATA_OFFSET_OCTET'),
    # #2896: constants moved to their package's const module, which the old
    # module no longer reads.
    ('pcapkit.protocols.application.ssl.protocol', 'TLS13_VERSION'),
    ('pcapkit.protocols.application.ssl.protocol', 'DTLS13_VERSION'),
    ('pcapkit.protocols.misc.pcap.header.schema', 'GLOBAL_HEADER_LEN'),
    ('pcapkit.protocols.misc.checksum.ip_pseudo.schema', 'IPV4_PSEUDO_LEN'),
    # #2882: the data models the data packages collected, now in each
    # reassembler's or flow tracer's own package, and the loggers of the modules
    # that became packages.
    ('pcapkit.foundation.reassembly.data', 'IP_Packet'),
    ('pcapkit.foundation.reassembly.data', 'IP_DatagramID'),
    ('pcapkit.foundation.reassembly.data', 'IP_Datagram'),
    ('pcapkit.foundation.reassembly.data', 'IP_Buffer'),
    ('pcapkit.foundation.reassembly.data', 'IP_BufferID'),
    ('pcapkit.foundation.reassembly.data', 'TCP_Packet'),
    ('pcapkit.foundation.reassembly.data', 'TCP_DatagramID'),
    ('pcapkit.foundation.reassembly.data', 'TCP_Datagram'),
    ('pcapkit.foundation.reassembly.data', 'TCP_Buffer'),
    ('pcapkit.foundation.reassembly.data', 'TCP_Fragment'),
    ('pcapkit.foundation.reassembly.data', 'TCP_HoleDescriptor'),
    ('pcapkit.foundation.reassembly.data', 'TCP_BufferID'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_Packet'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_DatagramID'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_Datagram'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_Buffer'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_Fragment'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_HoleDescriptor'),
    ('pcapkit.foundation.reassembly.data', 'DTLS_BufferID'),
    ('pcapkit.foundation.traceflow.data', 'TCP_Buffer'),
    ('pcapkit.foundation.traceflow.data', 'TCP_BufferID'),
    ('pcapkit.foundation.traceflow.data', 'TCP_Index'),
    ('pcapkit.foundation.traceflow.data', 'TCP_Packet'),
    ('pcapkit.foundation.reassembly.ip', 'logger'),
    ('pcapkit.foundation.traceflow.tcp', 'logger'),
    # #3105: shipped in 1.6.x, the OSPF header gone to the ospfv2 package.
    ('pcapkit.protocols.application.ospf', 'Schema_OSPF'),
    ('pcapkit.protocols.application.ospf', 'Schema_CryptographicAuthentication'),
    ('pcapkit.protocols.application.ospf', 'Data_OSPF'),
    ('pcapkit.protocols.application.ospf', 'Data_CryptographicAuthentication'),
    # #2934: the domain name codec ICMPv6's DNSSL option reads too, and its
    # pointer limit, moved to pcapkit.corekit.
    ('pcapkit.protocols.application.dns.schema', 'read_name'),
    ('pcapkit.protocols.application.dns.schema', 'make_name'),
    ('pcapkit.protocols.application.dns.schema', 'name_to_text'),
    ('pcapkit.protocols.application.dns.schema', 'text_to_labels'),
    ('pcapkit.protocols.application.dns.const', 'POINTER_LIMIT'),
)

#: Removed paths the old module still uses, as ``(old module, name, new home)``.
#: D1: the import stays, the export goes.
USED = (
    ('pcapkit.corekit.fields.field', 'NO_VALUE', 'pcapkit.corekit.sentinels'),
    ('pcapkit.corekit.enum', 'NO_DEFAULT', 'pcapkit.corekit.sentinels'),
    ('pcapkit.corekit.module', 'NULL', 'pcapkit.corekit.sentinels'),
    ('pcapkit.protocols.protocol', 'ABSENT', 'pcapkit.corekit.sentinels'),
    # #2674: the IP address fields' guards, moved with ``parse_ip_address``, and
    # the helpers the old modules still call.
    ('pcapkit.corekit.fields.ipaddress', '_reject_bool', 'pcapkit.corekit.schema.ipaddress'),
    ('pcapkit.corekit.fields.ipaddress', '_reraise_as_field_value_error',
     'pcapkit.corekit.schema.ipaddress'),
    ('pcapkit.protocols.internet.ipv6.schema', 'jumbo_payload_length', 'pcapkit.corekit.schema.jumbogram'),
    # #2883: the format constants the old modules still read.
    ('pcapkit.protocols.misc.pcap.header.schema', 'MAGIC_NUMBER', 'pcapkit.corekit.const.capture'),
    ('pcapkit.protocols.misc.pcap.frame.schema', 'RECORD_HEADER_LEN', 'pcapkit.corekit.const.capture'),
    ('pcapkit.protocols.misc.pcapng.schema', 'BYTE_ORDER_MAGIC', 'pcapkit.corekit.const.capture'),
    ('pcapkit.protocols.misc.pcapng.schema', 'GENERIC_BLOCK_MINIMUM', 'pcapkit.corekit.const.capture'),
    ('pcapkit.protocols.misc.pcapng.schema', 'BLOCK_MINIMUM', 'pcapkit.corekit.const.capture'),
    ('pcapkit.protocols.internet.ipv6.schema', 'IP_MAX_LENGTH', 'pcapkit.corekit.const.ip_header'),
    ('pcapkit.protocols.internet.ipv6.protocol', 'IPV6_HEADER_LEN', 'pcapkit.corekit.const.ip_header'),
    ('pcapkit.protocols.internet.ipv4.schema', 'IPV4_HEADER_LEN', 'pcapkit.corekit.const.ip_header'),
    ('pcapkit.protocols.internet.ah.schema', 'AH_HEADER_LEN', 'pcapkit.corekit.const.ip_header'),
    ('pcapkit.protocols.transport.tcp.schema', 'TCP_MIN_HEADER_LEN', 'pcapkit.corekit.const.tcp_header'),
    # #2897: the helper the old module still calls.
    ('pcapkit.protocols.link.loopback.protocol', 'family_byteorder', 'pcapkit.corekit.schema.byteorder'),
    # #2896: the constants documented at their old paths, now in their package's
    # const module. The old modules still read them, so they need no
    # versionremoved.
    ('pcapkit.protocols.application.dns.schema', 'HEADER_LENGTH', 'pcapkit.protocols.application.dns.const'),
    ('pcapkit.protocols.application.dns.schema', 'POINTER_LIMIT', 'pcapkit.corekit.const.domain_name'),
    ('pcapkit.protocols.application.http.protocol', '_HTTP2_PREFACE', 'pcapkit.protocols.application.http.const'),
    ('pcapkit.protocols.internet.hip.schema', 'LOCATOR_SET_LEN', 'pcapkit.protocols.internet.hip.const'),
    ('pcapkit.protocols.link.ieee802_11.protocol', 'SUBTYPE', 'pcapkit.protocols.link.ieee802_11.const'),
    ('pcapkit.protocols.link.ieee802_11.schema', 'CONTROL_WITH_ADDR2', 'pcapkit.protocols.link.ieee802_11.const'),
    ('pcapkit.protocols.misc.checksum.ip_pseudo.schema', 'IPV6_PSEUDO_LEN',
     'pcapkit.protocols.misc.checksum.ip_pseudo.const'),
    ('pcapkit.protocols.misc.pcapng.schema', 'PACKET_FLAGS', 'pcapkit.protocols.misc.pcapng.const'),
    ('pcapkit.protocols.transport.dccp.protocol', 'DCCP_MAX_HEADER_LEN', 'pcapkit.protocols.transport.dccp.const'),
    ('pcapkit.protocols.transport.dccp.schema', 'DCCP_MIN_HEADER_LEN', 'pcapkit.protocols.transport.dccp.const'),
    ('pcapkit.protocols.transport.dccp.schema', 'DCCP_SINGLE_OCTET_OPTION_MAX',
     'pcapkit.protocols.transport.dccp.const'),
    ('pcapkit.protocols.transport.dccp.schema', 'ACK_TYPES', 'pcapkit.protocols.transport.dccp.const'),
    ('pcapkit.protocols.transport.dccp.schema', 'SERVICE_TYPES', 'pcapkit.protocols.transport.dccp.const'),
    ('pcapkit.protocols.transport.dccp.schema', 'RESET_TYPE', 'pcapkit.protocols.transport.dccp.const'),
)

#: Every removed ``(old module, name)`` pair.
REMOVED = PURE + tuple((module, name) for module, name, _ in USED)

#: The paths that shipped in a release, as ``(old module, name, source file, docs page,
#: the version that removed it)``.
SHIPPED = (
    ('pcapkit.protocols.misc.pcapng', 'TLSKeyLabel',
     'pcapkit/protocols/misc/pcapng/protocol.py', 'pcapkit/protocols/misc/pcapng.rst', '1.5.0'),
    ('pcapkit.corekit.fields.field', 'NoValueType',
     'pcapkit/corekit/fields/field.py', 'pcapkit/corekit/fields/field.rst', '1.5.0'),
    ('pcapkit.protocols.internet.mh', 'NTPTimestamp',
     'pcapkit/protocols/internet/mh/protocol.py', 'pcapkit/protocols/internet/mh.rst', '1.5.0'),
    ('pcapkit.protocols.application.ftp', 'FTP_DATA',
     'pcapkit/protocols/application/ftp/protocol.py',
     'pcapkit/protocols/application/ftp.rst', '1.5.0'),
    # #2529: shipped in 1.5.x, moved to their own modules.
    ('pcapkit.protocols.application.rarp', 'DRARP',
     'pcapkit/protocols/application/rarp/protocol.py',
     'pcapkit/protocols/application/rarp.rst', '1.6.0'),
    ('pcapkit.protocols.link.arp', 'InARP',
     'pcapkit/protocols/link/arp/protocol.py',
     'pcapkit/protocols/link/arp.rst', '1.6.0'),
    # #2529: shipped in 1.5.x, renamed after their modules.
    ('pcapkit.protocols.application.httpv1', 'HTTP',
     'pcapkit/protocols/application/httpv1/protocol.py',
     'pcapkit/protocols/application/httpv1.rst', '1.6.0'),
    ('pcapkit.protocols.application.httpv2', 'HTTP',
     'pcapkit/protocols/application/httpv2/protocol.py',
     'pcapkit/protocols/application/httpv2.rst', '1.6.0'),
    ('pcapkit.protocols.schema.application.httpv1', 'HTTP',
     'pcapkit/protocols/application/httpv1/schema.py',
     'pcapkit/protocols/application/httpv1.rst', '1.6.0'),
    ('pcapkit.protocols.schema.application.httpv2', 'HTTP',
     'pcapkit/protocols/application/httpv2/schema.py',
     'pcapkit/protocols/application/httpv2.rst', '1.6.0'),
    ('pcapkit.protocols.data.application.httpv1', 'HTTP',
     'pcapkit/protocols/application/httpv1/data.py',
     'pcapkit/protocols/application/httpv1.rst', '1.6.0'),
    ('pcapkit.protocols.data.application.httpv2', 'HTTP',
     'pcapkit/protocols/application/httpv2/data.py',
     'pcapkit/protocols/application/httpv2.rst', '1.6.0'),
    # #2674: shipped in 1.5.x, moved to pcapkit.corekit.schema.
    ('pcapkit.corekit.fields.ipaddress', 'parse_ip_address',
     'pcapkit/corekit/fields/ipaddress.py', 'pcapkit/corekit/fields/ipaddress.rst', '1.6.0'),
    ('pcapkit.corekit.fields.ipaddress', '_reject_bool',
     'pcapkit/corekit/fields/ipaddress.py', 'pcapkit/corekit/fields/ipaddress.rst', '1.6.0'),
    ('pcapkit.protocols.schema.schema', 'keep_short_read',
     'pcapkit/protocols/schema.py', 'pcapkit/protocols/index.rst', '1.6.0'),
    ('pcapkit.protocols.schema.schema', 'replay_short_read',
     'pcapkit/protocols/schema.py', 'pcapkit/protocols/index.rst', '1.6.0'),
    ('pcapkit.protocols.schema.internet.ipv6', 'jumbo_payload_length',
     'pcapkit/protocols/internet/ipv6/schema.py', 'pcapkit/protocols/internet/ipv6.rst', '1.6.0'),
    # #2883: shipped in 1.6.x, moved to pcapkit.corekit.const.
    ('pcapkit.protocols.misc.pcap.header.schema', 'MAGIC_NUMBER',
     'pcapkit/protocols/misc/pcap/header/schema.py', 'pcapkit/protocols/misc/pcap.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcap.header.schema', 'RESOLUTION',
     'pcapkit/protocols/misc/pcap/header/schema.py', 'pcapkit/protocols/misc/pcap.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcap.header.schema', 'RESOLUTION_PLACES',
     'pcapkit/protocols/misc/pcap/header/schema.py', 'pcapkit/protocols/misc/pcap.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcap.frame.schema', 'RECORD_HEADER_LEN',
     'pcapkit/protocols/misc/pcap/frame/schema.py', 'pcapkit/protocols/misc/pcap.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcapng.schema', 'BYTE_ORDER_MAGIC',
     'pcapkit/protocols/misc/pcapng/schema.py', 'pcapkit/protocols/misc/pcapng.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcapng.schema', 'GENERIC_BLOCK_MINIMUM',
     'pcapkit/protocols/misc/pcapng/schema.py', 'pcapkit/protocols/misc/pcapng.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcapng.schema', 'BLOCK_MINIMUM',
     'pcapkit/protocols/misc/pcapng/schema.py', 'pcapkit/protocols/misc/pcapng.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcapng.schema', 'DEFAULT_RESOLUTION',
     'pcapkit/protocols/misc/pcapng/schema.py', 'pcapkit/protocols/misc/pcapng.rst', '1.7.0'),
    ('pcapkit.protocols.internet.ipv6.schema', 'IP_MAX_LENGTH',
     'pcapkit/protocols/internet/ipv6/schema.py', 'pcapkit/protocols/internet/ipv6.rst', '1.7.0'),
    ('pcapkit.protocols.internet.ipv6.protocol', 'IPV6_HEADER_LEN',
     'pcapkit/protocols/internet/ipv6/protocol.py', 'pcapkit/protocols/internet/ipv6.rst', '1.7.0'),
    ('pcapkit.protocols.internet.ipv6.protocol', 'IPV6_NEXT_HEADER_OFFSET',
     'pcapkit/protocols/internet/ipv6/protocol.py', 'pcapkit/protocols/internet/ipv6.rst', '1.7.0'),
    ('pcapkit.protocols.internet.ipv4.schema', 'IPV4_HEADER_LEN',
     'pcapkit/protocols/internet/ipv4/schema.py', 'pcapkit/protocols/internet/ipv4.rst', '1.7.0'),
    ('pcapkit.protocols.internet.ah.schema', 'AH_HEADER_LEN',
     'pcapkit/protocols/internet/ah/schema.py', 'pcapkit/protocols/internet/ah.rst', '1.7.0'),
    ('pcapkit.protocols.transport.tcp.schema', 'TCP_MIN_HEADER_LEN',
     'pcapkit/protocols/transport/tcp/schema.py', 'pcapkit/protocols/transport/tcp.rst', '1.7.0'),
    ('pcapkit.protocols.transport.tcp.schema', 'TCP_DATA_OFFSET_OCTET',
     'pcapkit/protocols/transport/tcp/schema.py', 'pcapkit/protocols/transport/tcp.rst', '1.7.0'),
    # #2897: shipped in 1.6.x, moved to pcapkit.corekit.schema.
    ('pcapkit.protocols.link.loopback.protocol', 'family_byteorder',
     'pcapkit/protocols/link/loopback/protocol.py', 'pcapkit/protocols/link/loopback.rst', '1.7.0'),
    # #2896: shipped in 1.6.x, moved to their package's const module.
    ('pcapkit.protocols.application.ssl.protocol', 'TLS13_VERSION',
     'pcapkit/protocols/application/ssl/protocol.py', 'pcapkit/protocols/application/ssl.rst', '1.7.0'),
    ('pcapkit.protocols.application.ssl.protocol', 'DTLS13_VERSION',
     'pcapkit/protocols/application/ssl/protocol.py', 'pcapkit/protocols/application/ssl.rst', '1.7.0'),
    ('pcapkit.protocols.misc.pcap.header.schema', 'GLOBAL_HEADER_LEN',
     'pcapkit/protocols/misc/pcap/header/schema.py', 'pcapkit/protocols/misc/pcap.rst', '1.7.0'),
    ('pcapkit.protocols.misc.checksum.ip_pseudo.schema', 'IPV4_PSEUDO_LEN',
     'pcapkit/protocols/misc/checksum/ip_pseudo/schema.py', 'pcapkit/protocols/misc/checksum.rst', '1.7.0'),
    # #2882: shipped in 1.6.x, bound by the modules that became packages.
    ('pcapkit.foundation.reassembly.ip', 'logger',
     'pcapkit/foundation/reassembly/ip/__init__.py', 'pcapkit/foundation/reassembly/ip/ip.rst', '1.7.0'),
    ('pcapkit.foundation.traceflow.tcp', 'logger',
     'pcapkit/foundation/traceflow/tcp/__init__.py', 'pcapkit/foundation/traceflow/tcp.rst', '1.7.0'),
    # #3105: shipped in 1.6.x, the OSPF header gone to the ospfv2 package.
    ('pcapkit.protocols.application.ospf', 'Schema_OSPF',
     'pcapkit/protocols/application/ospf/protocol.py', 'pcapkit/protocols/application/ospf.rst', '1.8.1'),
    ('pcapkit.protocols.application.ospf', 'Schema_CryptographicAuthentication',
     'pcapkit/protocols/application/ospf/protocol.py', 'pcapkit/protocols/application/ospf.rst', '1.8.1'),
    ('pcapkit.protocols.application.ospf', 'Data_OSPF',
     'pcapkit/protocols/application/ospf/protocol.py', 'pcapkit/protocols/application/ospf.rst', '1.8.1'),
    ('pcapkit.protocols.application.ospf', 'Data_CryptographicAuthentication',
     'pcapkit/protocols/application/ospf/protocol.py', 'pcapkit/protocols/application/ospf.rst', '1.8.1'),
    # #2934: shipped in 1.7.0 through 1.8.1, the four codec functions moved to
    # pcapkit.corekit.schema.domain_name and POINTER_LIMIT to
    # pcapkit.corekit.const.domain_name, both in 1.9.0.
    ('pcapkit.protocols.application.dns.schema', 'read_name',
     'pcapkit/protocols/application/dns/schema.py', 'pcapkit/protocols/application/dns.rst', '1.9.0'),
    ('pcapkit.protocols.application.dns.schema', 'make_name',
     'pcapkit/protocols/application/dns/schema.py', 'pcapkit/protocols/application/dns.rst', '1.9.0'),
    ('pcapkit.protocols.application.dns.schema', 'name_to_text',
     'pcapkit/protocols/application/dns/schema.py', 'pcapkit/protocols/application/dns.rst', '1.9.0'),
    ('pcapkit.protocols.application.dns.schema', 'text_to_labels',
     'pcapkit/protocols/application/dns/schema.py', 'pcapkit/protocols/application/dns.rst', '1.9.0'),
    ('pcapkit.protocols.application.dns.const', 'POINTER_LIMIT',
     'pcapkit/protocols/application/dns/const.py', 'pcapkit/protocols/application/dns.rst', '1.9.0'),
)

#: Shipped modules that moved whole, as ``(old module, the module recording its
#: removal, docs page, the version that removed it)``.
MOVED_MODULES = (
    # #2529: shipped in 1.5.x, renamed after the class they hold.
    ('pcapkit.protocols.misc.null', 'pcapkit.protocols.misc.no_payload.protocol',
     'pcapkit/protocols/misc/no_payload.rst', '1.6.0'),
    ('pcapkit.protocols.schema.misc.null', 'pcapkit.protocols.misc.no_payload.protocol',
     'pcapkit/protocols/misc/no_payload.rst', '1.6.0'),
    ('pcapkit.protocols.data.misc.null', 'pcapkit.protocols.misc.no_payload.protocol',
     'pcapkit/protocols/misc/no_payload.rst', '1.6.0'),
    # #2674: shipped in 1.5.x, moved whole into pcapkit.corekit.schema.
    ('pcapkit.corekit.fields.byteorder', 'pcapkit.corekit.schema.byteorder',
     'pcapkit/corekit/schema/byteorder.rst', '1.6.0'),
    # #2882: shipped in 1.6.x, moved whole into each reassembler's or flow
    # tracer's package, or beside its base.
    ('pcapkit.foundation.reassembly.data.data', 'pcapkit.foundation.reassembly.data',
     'pcapkit/foundation/reassembly/index.rst', '1.7.0'),
    ('pcapkit.foundation.reassembly.data.ip', 'pcapkit.foundation.reassembly.ip.data',
     'pcapkit/foundation/reassembly/ip/ip.rst', '1.7.0'),
    ('pcapkit.foundation.reassembly.data.tcp', 'pcapkit.foundation.reassembly.tcp.data',
     'pcapkit/foundation/reassembly/tcp.rst', '1.7.0'),
    ('pcapkit.foundation.reassembly.data.dtls', 'pcapkit.foundation.reassembly.dtls.data',
     'pcapkit/foundation/reassembly/dtls.rst', '1.7.0'),
    ('pcapkit.foundation.traceflow.data.data', 'pcapkit.foundation.traceflow.data',
     'pcapkit/foundation/traceflow/index.rst', '1.7.0'),
    ('pcapkit.foundation.traceflow.data.tcp', 'pcapkit.foundation.traceflow.tcp.data',
     'pcapkit/foundation/traceflow/tcp.rst', '1.7.0'),
    # #3105: shipped in 1.6.x, moved whole into the ospfv2 package.
    ('pcapkit.protocols.application.ospf.schema', 'pcapkit.protocols.application.ospf.protocol',
     'pcapkit/protocols/application/ospf.rst', '1.8.1'),
    ('pcapkit.protocols.application.ospf.data', 'pcapkit.protocols.application.ospf.protocol',
     'pcapkit/protocols/application/ospf.rst', '1.8.1'),
    # #3153: shipped in 1.6.0 and 1.7.0, renamed so that their words are
    # separated by underscores.
    ('pcapkit.corekit.schema.shortread', 'pcapkit.corekit.schema.short_read',
     'pcapkit/corekit/schema/short_read.rst', '1.9.0'),
    ('pcapkit.corekit.schema.extlen', 'pcapkit.corekit.schema.ext_len',
     'pcapkit/corekit/schema/ext_len.rst', '1.9.0'),
    ('pcapkit.corekit.const.ipheader', 'pcapkit.corekit.const.ip_header',
     'pcapkit/corekit/const/ip_header.rst', '1.9.0'),
    ('pcapkit.corekit.const.tcpheader', 'pcapkit.corekit.const.tcp_header',
     'pcapkit/corekit/const/tcp_header.rst', '1.9.0'),
)


#: The names the latest release shipped under :mod:`pcapkit.protocols`, which
#: :file:`util/shipped_names.py` reads from its tag (CI checks out no tags).
SHIPPED_NAMES = ROOT / 'tests' / 'project' / 'shipped_names_fixtures' / 'v1.6.0.json'

#: A ``versionremoved`` block, as its indentation and its body: the lines indented past it.
REMOVAL_BLOCK = re.compile(r'(?m)^(?P<indent>[ \t]*)\.\. versionremoved::[^\n]*\n'
                           r'(?P<body>(?:(?P=indent)[ \t]+[^\n]*\n|[ \t]*\n)*)')

#: A module whose public names :meth:`TestShippedNames.test_the_generator_reads_what_a_module_binds`
#: reads.
SAMPLE = """\
from typing import TYPE_CHECKING
from pcapkit.protocols.protocol import Protocol as Base
__all__ = ['Kept', 'Base']
if TYPE_CHECKING:
    Hidden = int
else:
    Shown = int
try:
    Tried = 1
except ImportError:
    Handled = 2
LIMIT, (PAIR, _PRIVATE) = 1, (2, 3)
Base.__proto__[1] = None
class Kept: ...
def helper(): ...
"""


def _sources() -> 'list[pathlib.Path]':
    """Every Python file a reader could live in."""
    files = []  # type: list[pathlib.Path]
    for top in ('pcapkit', 'examples', 'util', 'tests'):
        files.extend(sorted((ROOT / top).rglob('*.py')))
    return files


def _docs_dir() -> 'pathlib.Path':
    """The Sphinx source directory."""
    return ROOT / 'docs' / 'source'


def _removed_by_module() -> 'dict[str, set[str]]':
    """The removed names, grouped by the old module they left."""
    removed = {}  # type: dict[str, set[str]]
    for module_name, name in REMOVED:
        removed.setdefault(module_name, set()).add(name)
    return removed


def _dotted(node: 'ast.expr') -> 'str | None':
    """The dotted name an attribute chain spells, or :data:`None`."""
    parts = []  # type: list[str]
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return '.'.join(reversed(parts))


#: Wording that claims a name is still reachable somewhere.
CLAIM = re.compile(r'importable from|still importable|re-exported|available as', re.IGNORECASE)


def _sentences(text: 'str') -> 'list[str]':
    """The sentences of ``text``, each on one line."""
    sentences = []  # type: list[str]
    for paragraph in re.split(r'\n\s*\n', text):
        sentences.extend(re.split(r'(?<=[.!?])\s+', ' '.join(paragraph.split())))
    return sentences


def _claims(text: 'str', owner: 'str | None' = None) -> 'list[str]':
    """Removed paths a sentence of ``text`` claims a name is reachable at.

    A sentence counts only when it carries :data:`CLAIM` wording and names a
    removed ``(old module, name)`` pair: the dotted path itself, or the old
    module with the name -- given in the sentence, or by ``owner``, the object
    whose docstring ``text`` is.

    """
    found = []  # type: list[str]
    for sentence in _sentences(text):
        if CLAIM.search(sentence) is None:
            continue
        for module_name, name in REMOVED:
            module_re, name_re = re.escape(module_name), re.escape(name)
            if re.search(rf'(?<![\w.]){module_re}\.{name_re}(?!\w)', sentence) is not None \
                    or (re.search(rf'(?<![\w.]){module_re}(?!\w|\.\w)', sentence) is not None
                        and (owner == name
                             or re.search(rf'(?<![\w.]){name_re}(?!\w)', sentence) is not None)):
                found.append(f'{module_name}.{name}: {sentence}')
    return found


def _removal_notes() -> 'str':
    """Every ``versionremoved`` block's body on a docs page or in a protocol module's docstring.

    The changelogs are left out: they record a removal, rather than standing at
    the path it left.

    """
    bodies = []  # type: list[str]
    for page in sorted(_docs_dir().rglob('*.rst')):
        if 'changelog' not in page.relative_to(_docs_dir()).parts:
            bodies.extend(m.group('body') for m in REMOVAL_BLOCK.finditer(page.read_text(encoding='utf-8')))
    for path in sorted((ROOT / 'pcapkit' / 'protocols').rglob('*.py')):
        docstring = ast.get_docstring(ast.parse(path.read_text(encoding='utf-8')), clean=False) or ''
        bodies.extend(m.group('body') for m in REMOVAL_BLOCK.finditer(docstring))
    return '\n'.join(bodies)


def _module(name: 'str') -> 'object':
    """The module ``name`` imports as, or :data:`None` where it no longer imports."""
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


def _source_names(module: 'object') -> 'set[str]':
    """The names ``module``'s source binds, read as :func:`util.shipped_names.defined` reads the tag.

    These include a TypedDict bound only for Sphinx, which the fixture lists and
    the module lacks at run time.

    """
    tree = ast.parse(pathlib.Path(inspect.getfile(module)).read_text(encoding='utf-8'))
    return set(shipped_names.defined(tree.body))


class TestNotExported(unittest.TestCase):
    """No removed name is in its old module's ``__all__``."""

    def test_removed_names_are_not_in_all(self) -> 'None':
        for module_name, name in REMOVED:
            with self.subTest(module=module_name, name=name):
                module = importlib.import_module(module_name)
                self.assertNotIn(name, module.__all__)


class TestNotBound(unittest.TestCase):
    """A pure re-export is gone; a name still used is the new home's object."""

    def test_pure_re_exports_are_not_bound(self) -> 'None':
        for module_name, name in PURE:
            with self.subTest(module=module_name, name=name):
                module = importlib.import_module(module_name)
                self.assertFalse(hasattr(module, name))

    def test_used_names_are_the_new_homes_object(self) -> 'None':
        for module_name, name, home in USED:
            with self.subTest(module=module_name, name=name):
                module = importlib.import_module(module_name)
                self.assertIs(getattr(module, name), getattr(importlib.import_module(home), name))


class TestNoReader(unittest.TestCase):
    """Every other reader imports the name from its new home."""

    def test_no_import_from_an_old_path(self) -> 'None':
        removed = _removed_by_module()
        found = []  # type: list[str]
        for path in _sources():
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module in removed:
                    for alias in node.names:
                        if alias.name in removed[node.module]:
                            found.append(f'{path.relative_to(ROOT)}:{node.lineno}: '
                                         f'{node.module}.{alias.name}')
        self.assertEqual(found, [])

    def test_no_attribute_read_through_an_old_module(self) -> 'None':
        removed = _removed_by_module()
        found = []  # type: list[str]
        for path in _sources():
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            # An old module bound under a local name, and the top-level names a
            # plain ``import a.b.c`` binds, through which ``a.b.c.NAME`` reads.
            aliases = {}  # type: dict[str, str]
            roots = set()  # type: set[str]
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.asname is None:
                            roots.add(alias.name.partition('.')[0])
                        elif alias.name in removed:
                            aliases[alias.asname] = alias.name
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    for alias in node.names:
                        if f'{node.module}.{alias.name}' in removed:
                            aliases[alias.asname or alias.name] = f'{node.module}.{alias.name}'
            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
                    continue
                base = _dotted(node.value)
                if base in aliases:
                    module_name = aliases[base]
                elif base in removed and base.partition('.')[0] in roots:
                    module_name = base
                else:
                    continue
                if node.attr in removed[module_name]:
                    found.append(f'{path.relative_to(ROOT)}:{node.lineno}: '
                                 f'{module_name}.{node.attr}')
        self.assertEqual(found, [])


class TestNotDocumented(unittest.TestCase):
    """No ``auto*`` directive documents a removed name at its old path."""

    def test_no_directive_names_an_old_path(self) -> 'None':
        found = []  # type: list[str]
        for page in sorted(_docs_dir().rglob('*.rst')):
            text = page.read_text(encoding='utf-8')
            for module_name, name in REMOVED:
                pattern = rf'(?m)^\s*\.\. auto\w+:: {re.escape(module_name)}\.{re.escape(name)}\s*$'
                if re.search(pattern, text):
                    found.append(f'{page.relative_to(ROOT)}: {module_name}.{name}')
        self.assertEqual(found, [])


class TestNoReExportProse(unittest.TestCase):
    """No prose says a removed name is still reachable at its old path."""

    def test_no_docstring_claims_an_old_path(self) -> 'None':
        found = []  # type: list[str]
        for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = None if isinstance(node, ast.Module) else node.name
                    for claim in _claims(ast.get_docstring(node) or '', owner):
                        found.append(f'{path.relative_to(ROOT)}: {claim}')
        self.assertEqual(found, [])

    def test_no_docs_page_claims_an_old_path(self) -> 'None':
        found = []  # type: list[str]
        for page in sorted(_docs_dir().rglob('*.rst')):
            for claim in _claims(page.read_text(encoding='utf-8')):
                found.append(f'{page.relative_to(ROOT)}: {claim}')
        self.assertEqual(found, [])


class TestVersionRemoved(unittest.TestCase):
    """A path that shipped in a release is recorded as removed, twice."""

    def test_docstring_and_docs_page_carry_the_directive(self) -> 'None':
        for module_name, name, source, page, version in SHIPPED:
            old_path = f'``{module_name}.{name}``'
            # the docstring of the module holding the note now, read from its
            # file: the old module may have gone with its tree (#2534)
            tree = ast.parse((ROOT / source).read_text(encoding='utf-8'))
            for label, text in (('docstring', ast.get_docstring(tree, clean=False) or ''),
                                ('docs page', (_docs_dir() / page).read_text(encoding='utf-8'))):
                with self.subTest(path=f'{module_name}.{name}', where=label):
                    blocks = re.findall(rf'(?ms)^\.\. versionremoved:: {re.escape(version)}\n\n(.*?)(?=^\S|\Z)',
                                        text)
                    self.assertTrue(any(old_path in block for block in blocks),
                                    f'no versionremoved:: {version} block names {old_path} in {label}')
            self.assertTrue((ROOT / source).is_file())


class TestMovedModules(unittest.TestCase):
    """A shipped module that moved whole is gone, and recorded as removed, twice."""

    def test_the_old_module_does_not_import(self) -> 'None':
        for old, _, _, _ in MOVED_MODULES:
            with self.subTest(module=old):
                with self.assertRaises(ModuleNotFoundError):
                    importlib.import_module(old)

    def test_docstring_and_docs_page_carry_the_directive(self) -> 'None':
        for old, recorder, page, version in MOVED_MODULES:
            module = importlib.import_module(recorder)
            for label, text in (('docstring', module.__doc__ or ''),
                                ('docs page', (_docs_dir() / page).read_text(encoding='utf-8'))):
                with self.subTest(module=old, where=label):
                    blocks = re.findall(rf'(?ms)^\.\. versionremoved:: {re.escape(version)}\n\n(.*?)(?=^\S|\Z)',
                                        text)
                    self.assertTrue(any(f'``{old}``' in block for block in blocks),
                                    f'no versionremoved:: {version} block names ``{old}`` in {label}')


class TestShippedNames(unittest.TestCase):
    """Each name the release shipped under :mod:`pcapkit.protocols` resolves, or is recorded as gone."""

    def setUp(self) -> 'None':
        self.fixture = json.loads(SHIPPED_NAMES.read_text(encoding='utf-8'))

    def test_the_fixture_names_its_release(self) -> 'None':
        """The fixture names the tag and commit it was read from, and the command that wrote it."""
        tag = SHIPPED_NAMES.stem
        self.assertEqual(self.fixture['tag'], tag)
        self.assertRegex(self.fixture['commit'], r'^[0-9a-f]{40}$')
        self.assertEqual(self.fixture['generator'], f'python3 util/shipped_names.py {tag}')
        self.assertEqual(self.fixture['scope'], shipped_names.SCOPE)
        self.assertIn('pcapkit.protocols.protocol', self.fixture['modules'])

    def test_every_shipped_name_resolves_or_is_recorded(self) -> 'None':
        """A name gone from its old path has a ``versionremoved`` naming that path (#2534).

        One naming the module stands for the name where the module went whole,
        or where the module only re-exported the name. A name bound only for
        Sphinx resolves while the module's source still binds it.

        """
        notes = _removal_notes()
        missing = []  # type: list[str]
        for module_name, names in sorted(self.fixture['modules'].items()):
            module = _module(module_name)
            source = set() if module is None else _source_names(module)  # type: set[str]
            for name in names['defined'] + names['exported'] + names['documented']:
                if module is not None and (hasattr(module, name) or name in source):
                    continue
                if f'``{module_name}.{name}``' in notes:
                    continue
                if f'``{module_name}``' in notes and (module is None or name in names['exported']):
                    continue
                missing.append(f'{module_name}.{name}')
        self.assertEqual(missing, [], 'record each in a versionremoved naming its old path')

    def test_the_generator_reads_what_a_module_binds(self) -> 'None':
        """:file:`util/shipped_names.py` reads the names bound at run time, the re-exports and the documented."""
        tree = ast.parse(SAMPLE)
        self.assertEqual(shipped_names.defined(tree.body),
                         ['__all__', 'Shown', 'Tried', 'Handled', 'LIMIT', 'PAIR', '_PRIVATE', 'Kept',
                          'helper'])
        self.assertEqual(shipped_names.exported(tree), ['Kept', 'Base'])
        self.assertEqual(shipped_names.module_name('pcapkit/protocols/link/__init__.py'),
                         'pcapkit.protocols.link')
        page = ('.. module:: pcapkit.protocols.link.vlan\n\n'
                '.. autoclass:: pcapkit.protocols.link.vlan.VLAN\n   :members:\n\n'
                '   .. autoattribute:: pcapkit.protocols.link.vlan.Nested\n\n'
                '.. data:: _CACHE\n\n.. autofunction:: helper\n')
        self.assertEqual(shipped_names.documented(page, {'pcapkit.protocols.link.vlan'}),
                         {'pcapkit.protocols.link.vlan': {'VLAN', '_CACHE', 'helper'}})


if __name__ == '__main__':
    unittest.main()
