# -*- coding: utf-8 -*-
"""The ``sctp-chunk``, ``sctp-parameter`` and ``sctp-cause`` families: SCTP chunks,
parameters and error causes.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: Header fields shared by every constructed SCTP packet. ``chksum`` is pinned
#: rather than left to the CRC32c path, so a mismatch points at the chunk under
#: test and not at a recomputed checksum.
SCTP_BASE = {
    'srcport': 50000, 'dstport': 80, 'vtag': 0x11223344,
    'chksum': b'\x00\x00\x00\x00',
}


def _sctp_chunk_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP.__chunk__


def _sctp_chunk_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter

    # The three-octet payloads are deliberate: they make each item's length
    # 3 (mod 4), so every case runs the PaddingField path instead of landing
    # already aligned.
    return {
        # ``data=b''`` is rejected outright -- RFC 9260 s3.3.1 wants at least
        # one octet of user data -- so this override is required, not cosmetic.
        Enum_Chunk.Payload_Data: {'data': b'\x01\x02\x03'},
        Enum_Chunk.Initiation: {
            'parameters': [(Enum_Parameter.State_Cookie, {'cookie': b'\x01\x02\x03'})]},
        Enum_Chunk.Initiation_Acknowledgement: {
            'parameters': [(Enum_Parameter.State_Cookie, {'cookie': b'\x01\x02\x03'})]},
        Enum_Chunk.Selective_Acknowledgement: {'gap_blocks': [(1, 2)], 'dup_tsn': [3]},
        # RFC 9260 s3.3.5 and s3.3.6 mandate exactly one Heartbeat Info
        # parameter, so the default -- none at all -- is structurally invalid.
        Enum_Chunk.Heartbeat_Request: {
            'parameters': [(Enum_Parameter.Heartbeat_Info, {'info': b'\x01\x02\x03'})]},
        Enum_Chunk.Heartbeat_Acknowledgement: {
            'parameters': [(Enum_Parameter.Heartbeat_Info, {'info': b'\x01\x02\x03'})]},
        Enum_Chunk.Abort: {
            'error': [(Enum_CauseCode.User_Initiated_Abort, {'info': b'\x01\x02\x03'})]},
        # ``_make_chunk_error`` documents "one or more error causes"; the
        # default gives zero.
        Enum_Chunk.Operation_Error: {
            'error': [(Enum_CauseCode.Protocol_Violation, {'info': b'\x01\x02\x03'})]},
        Enum_Chunk.State_Cookie: {'cookie': b'\x01\x02\x03'},
    }


def _sctp_chunk_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP(chunks=[(code, kwargs)], **SCTP_BASE)


def _sctp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP(octets, len(octets))


def _sctp_extract(parsed: 'Any') -> 'Any':
    return parsed.info.chunks


def _sctp_rebuild(chunks: 'Any') -> 'Any':
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP(chunks=chunks, **SCTP_BASE)


def _sctp_param_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP.__parameter__


def _sctp_param_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
    return {
        Enum_Parameter.Heartbeat_Info: {'info': b'\x01\x02\x03'},
        Enum_Parameter.IPv4_Address: {'address': '192.0.2.1'},
        Enum_Parameter.IPv6_Address: {'address': '2001:db8::1'},
        Enum_Parameter.State_Cookie: {'cookie': b'\x01\x02\x03'},
        # A complete unrecognised TLV -- type 0xffff, length 5, one value
        # octet -- rather than the empty default, which is not a TLV at all.
        Enum_Parameter.Unrecognized_Parameter: {'value': b'\xff\xff\x00\x05\x01'},
        Enum_Parameter.Host_Name_Address: {'name': b'localhost\x00'},
        Enum_Parameter.Supported_Address_Types: {
            'types': [Enum_Parameter.IPv4_Address, Enum_Parameter.IPv6_Address]},
    }


def _sctp_param_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.protocols.transport.sctp.protocol import SCTP

    # A parameter is not a top-level item: it travels inside a chunk, and
    # HEARTBEAT is the smallest chunk that carries an arbitrary one.
    return SCTP(chunks=[(Enum_Chunk.Heartbeat_Request,
                         {'parameters': [(code, kwargs)]})], **SCTP_BASE)


def _sctp_cause_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP.__cause__


def _sctp_cause_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
    from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
    return {
        Enum_CauseCode.Missing_Mandatory_Parameter: {
            'types': [Enum_Parameter.State_Cookie]},
        # The causes below carry an embedded TLV, and each one's default
        # is a zero-length value, i.e. not a TLV.
        Enum_CauseCode.Unresolvable_Address: {
            'value': b'\x00\x0b\x00\x0elocalhost\x00'},
        Enum_CauseCode.Unrecognized_Chunk_Type: {'value': b'\xff\x00\x00\x05\x01'},
        Enum_CauseCode.Unrecognized_Parameters: {'value': b'\xff\xff\x00\x05\x01'},
        Enum_CauseCode.Restart_of_an_Association_with_New_Addresses: {
            'value': b'\x00\x05\x00\x08\xc0\x00\x02\x01'},
        Enum_CauseCode.User_Initiated_Abort: {'info': b'\x01\x02\x03'},
        Enum_CauseCode.Protocol_Violation: {'info': b'\x01\x02\x03'},
    }


def _sctp_cause_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.protocols.transport.sctp.protocol import SCTP

    # An error cause travels inside an ERROR (or ABORT) chunk, under the
    # keyword ``error`` rather than ``causes``.
    return SCTP(chunks=[(Enum_Chunk.Operation_Error,
                         {'error': [(code, kwargs)]})], **SCTP_BASE)


#: The families this module adds.
FAMILIES = (
    generator.Family('sctp-chunk', _sctp_chunk_registry, _sctp_chunk_overrides,
                     _sctp_chunk_build, _sctp_parse, _sctp_extract, _sctp_rebuild,
                     capture='options-transport.pcap', envelope='ipv4', proto=132),
    generator.Family('sctp-parameter', _sctp_param_registry, _sctp_param_overrides,
                     _sctp_param_build, _sctp_parse, _sctp_extract, _sctp_rebuild,
                     capture='options-transport.pcap', envelope='ipv4', proto=132),
    generator.Family('sctp-cause', _sctp_cause_registry, _sctp_cause_overrides,
                     _sctp_cause_build, _sctp_parse, _sctp_extract, _sctp_rebuild,
                     capture='options-transport.pcap', envelope='ipv4', proto=132),
)
