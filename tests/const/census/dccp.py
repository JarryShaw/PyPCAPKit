# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.dccp`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.dccp.ack_vector_state:AckVectorState': 'int',
    'pcapkit.const.dccp.drop_code:DropCode': 'int',
    'pcapkit.const.dccp.feature:Feature': 'int',
    'pcapkit.const.dccp.option:Option': 'int',
    'pcapkit.const.dccp.packet_type:PacketType': 'int',
    'pcapkit.const.dccp.reset_code:ResetCode': 'int',
}
