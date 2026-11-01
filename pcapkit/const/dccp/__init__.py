# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.transport.dccp.DCCP` Constant Enumerations
==========================================================================

.. module:: pcapkit.const.dccp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.transport.dccp.DCCP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`DCCP_PacketType <pcapkit.const.dccp.packet_type.PacketType>`
     - DCCP Packet Types [*]_
   * - :class:`DCCP_ResetCode <pcapkit.const.dccp.reset_code.ResetCode>`
     - DCCP Reset Codes [*]_
   * - :class:`DCCP_Option <pcapkit.const.dccp.option.Option>`
     - DCCP Option Types [*]_
   * - :class:`DCCP_Feature <pcapkit.const.dccp.feature.Feature>`
     - DCCP Feature Numbers [*]_
   * - :class:`DCCP_AckVectorState <pcapkit.const.dccp.ack_vector_state.AckVectorState>`
     - DCCP Ack Vector States [*]_
   * - :class:`DCCP_DropCode <pcapkit.const.dccp.drop_code.DropCode>`
     - DCCP Drop Codes [*]_

.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-1
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-3
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-5
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-7
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-10
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-11

"""

from pcapkit.const.dccp.ack_vector_state import AckVectorState as DCCP_AckVectorState
from pcapkit.const.dccp.drop_code import DropCode as DCCP_DropCode
from pcapkit.const.dccp.feature import Feature as DCCP_Feature
from pcapkit.const.dccp.option import Option as DCCP_Option
from pcapkit.const.dccp.packet_type import PacketType as DCCP_PacketType
from pcapkit.const.dccp.reset_code import ResetCode as DCCP_ResetCode

__all__ = ['DCCP_PacketType', 'DCCP_ResetCode', 'DCCP_Option', 'DCCP_Feature',
           'DCCP_AckVectorState', 'DCCP_DropCode']
