# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.sctp`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.sctp.cause_code:CauseCode': 'int',
    'pcapkit.const.sctp.chunk:Chunk': 'int',
    'pcapkit.const.sctp.parameter:Parameter': 'int',
    'pcapkit.const.sctp.payload_protocol_identifier:PayloadProtocolIdentifier': 'int',
}
