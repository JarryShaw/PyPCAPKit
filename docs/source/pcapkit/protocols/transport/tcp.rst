TCP - Transmission Control Protocol
===================================

.. module:: pcapkit.protocols.transport.tcp
.. module:: pcapkit.protocols.transport.tcp.protocol

:mod:`pcapkit.protocols.transport.tcp.protocol` contains
:class:`~pcapkit.protocols.transport.tcp.protocol.TCP` only,
which implements the extractor for Transmission Control
Protocol (TCP) [*]_, whose structure is described as
below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``tcp.srcport``           Source Port
  2          16   ``tcp.dstport``           Destination Port
  4          32   ``tcp.seq``               Sequence Number
  8          64   ``tcp.ack``               Acknowledgement Number (if ACK set)
  12         96   ``tcp.hdr_len``           Data Offset
  12        100   ``tcp.flags.reserved``    Reserved (must be ``\x00``)
  12        103   ``tcp.flags.ns``          ECN Concealment Protection (NS)
  13        104   ``tcp.flags.cwr``         Congestion Window Reduced (CWR)
  13        105   ``tcp.flags.ece``         ECN-Echo (ECE)
  13        106   ``tcp.flags.urg``         Urgent (URG)
  13        107   ``tcp.flags.ack``         Acknowledgement (ACK)
  13        108   ``tcp.flags.psh``         Push Function (PSH)
  13        109   ``tcp.flags.rst``         Reset Connection (RST)
  13        110   ``tcp.flags.syn``         Synchronize Sequence Numbers (SYN)
  13        111   ``tcp.flags.fin``         Last Packet from Sender (FIN)
  14        112   ``tcp.window_size``       Size of Receive Window
  16        128   ``tcp.checksum``          Checksum
  18        144   ``tcp.urgent_pointer``    Urgent Pointer (if URG set)
  20        160   ``tcp.options``           TCP Options (if data offset > 5)
======= ========= ========================= =======================================

.. autoclass:: pcapkit.protocols.transport.tcp.protocol.TCP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst
   .. autoproperty:: connection

   .. automethod:: register_option
   .. automethod:: register_mp_option

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data
   .. automethod:: _verify_pseudo_checksum

   .. automethod:: _read_tcp_options
   .. automethod:: _read_mode_donone
   .. automethod:: _read_mode_eool
   .. automethod:: _read_mode_nop
   .. automethod:: _read_mode_mss
   .. automethod:: _read_mode_ws
   .. automethod:: _read_mode_sackpmt
   .. automethod:: _read_mode_sack
   .. automethod:: _read_mode_echo
   .. automethod:: _read_mode_echore
   .. automethod:: _read_mode_ts
   .. automethod:: _read_mode_poc
   .. automethod:: _read_mode_pocsp
   .. automethod:: _read_mode_cc
   .. automethod:: _read_mode_ccnew
   .. automethod:: _read_mode_ccecho
   .. automethod:: _read_mode_chkreq
   .. automethod:: _read_mode_chksum
   .. automethod:: _read_mode_sig
   .. automethod:: _read_mode_qs
   .. automethod:: _read_mode_timeout
   .. automethod:: _read_mode_ao
   .. automethod:: _read_mode_mp
   .. automethod:: _read_mode_fastopen

   .. automethod:: _read_mptcp_unknown
   .. automethod:: _read_mptcp_capable
   .. automethod:: _read_mptcp_join
   .. automethod:: _read_mptcp_dss
   .. automethod:: _read_mptcp_addaddr
   .. automethod:: _read_mptcp_remove
   .. automethod:: _read_mptcp_prio
   .. automethod:: _read_mptcp_fail
   .. automethod:: _read_mptcp_fastclose

   .. automethod:: _read_join_syn
   .. automethod:: _read_join_synack
   .. automethod:: _read_join_ack

   .. automethod:: _make_tcp_options
   .. automethod:: _make_mode_donone
   .. automethod:: _make_mode_eool
   .. automethod:: _make_mode_nop
   .. automethod:: _make_mode_mss
   .. automethod:: _make_mode_ws
   .. automethod:: _make_mode_sackpmt
   .. automethod:: _make_mode_sack
   .. automethod:: _make_mode_echo
   .. automethod:: _make_mode_echore
   .. automethod:: _make_mode_ts
   .. automethod:: _make_mode_poc
   .. automethod:: _make_mode_pocsp
   .. automethod:: _make_mode_cc
   .. automethod:: _make_mode_ccnew
   .. automethod:: _make_mode_ccecho
   .. automethod:: _make_mode_chkreq
   .. automethod:: _make_mode_chksum
   .. automethod:: _make_mode_sig
   .. automethod:: _make_mode_qs
   .. automethod:: _make_mode_timeout
   .. automethod:: _make_mode_ao
   .. automethod:: _make_mode_mp
   .. automethod:: _make_mode_fastopen

   .. automethod:: _make_mptcp_unknown
   .. automethod:: _make_mptcp_capable
   .. automethod:: _make_mptcp_join
   .. automethod:: _make_mptcp_dss
   .. automethod:: _make_mptcp_addaddr
   .. automethod:: _make_mptcp_remove
   .. automethod:: _make_mptcp_prio
   .. automethod:: _make_mptcp_fail
   .. automethod:: _make_mptcp_fastclose

   .. automethod:: _make_join_syn
   .. automethod:: _make_join_synack
   .. automethod:: _make_join_ack

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:
   .. autoattribute:: __option__
      :no-value:
   .. autoattribute:: __mp_option__
      :no-value:

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.transport.tcp.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.transport.tcp``, with no alias: the module moved here
   (:issue:`2534`).

.. autodata:: pcapkit.protocols.transport.tcp.schema.TCP_MIN_HEADER_LEN

.. autodata:: pcapkit.protocols.transport.tcp.schema.TCP_DATA_OFFSET_OCTET

.. autoclass:: pcapkit.protocols.transport.tcp.schema.TCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.EndOfOptionList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.NoOperation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MaximumSegmentSize
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.WindowScale
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.SACKPermitted
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.SACK
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.SACKBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.EchoReply
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.Timestamps
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.PartialOrderConnectionPermitted
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.PartialOrderServiceProfile
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.CC
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.CCNew
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.CCEcho
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.AlternateChecksumRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.AlternateChecksumData(kind, length, data)
   :no-members:
   :show-inheritance:

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MD5Signature(kind, length, digest)
   :no-members:
   :show-inheritance:

   .. autoattribute:: digest

.. autoclass:: pcapkit.protocols.transport.tcp.schema.QuickStartResponse
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.UserTimeout
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.Authentication
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.FastOpenCookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema._MPTCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPUnknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPCapable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPJoin
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPJoinSYN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPJoinSYNACK
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPJoinACK
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPDSS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPAddAddress
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPRemoveAddress
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPPriority
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPFallback
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPFastclose
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.transport.tcp.schema.OffsetFlag
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.POCProfile
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.QuickStartFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.QuickStartNonce
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.TimeoutInfo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtypeTest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtypeUnknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtypeCapable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPCapableFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtypeJoin
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtype
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPDSSFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtypeAddAddress
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.schema.MPTCPSubtypePriority
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.transport.tcp.schema.mptcp_data_selector
.. autofunction:: pcapkit.protocols.transport.tcp.schema.mptcp_add_address_selector
.. autofunction:: pcapkit.protocols.transport.tcp.schema.mptcp_dss_checksum
.. autofunction:: pcapkit.protocols.transport.tcp.schema.mptcp_dss_ack_selector
.. autofunction:: pcapkit.protocols.transport.tcp.schema.mptcp_dss_dsn_selector

Data Models
-----------

.. module:: pcapkit.protocols.transport.tcp.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.transport.tcp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.transport.tcp.data.TCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.EndOfOptionList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.NoOperation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MaximumSegmentSize
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.WindowScale
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.SACKPermitted
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.SACK
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.SACKBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.EchoReply
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.Timestamps
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.PartialOrderConnectionPermitted
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.PartialOrderServiceProfile
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.CC
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.CCNew
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.CCEcho
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.AlternateChecksumRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.AlternateChecksumData(kind, length, data)
   :no-members:
   :show-inheritance:

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.transport.tcp.data.MD5Signature(kind, length, digest)
   :no-members:
   :show-inheritance:

   .. autoattribute:: digest

.. autoclass:: pcapkit.protocols.transport.tcp.data.QuickStartResponse
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.UserTimeout
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.Authentication
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.FastOpenCookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPUnknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPCapable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPCapableFlag
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPJoin
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPJoinSYN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPJoinSYNACK
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPJoinACK
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPDSS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPAddAddress
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPRemoveAddress
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPPriority
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPFallback
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.transport.tcp.data.MPTCPFastclose
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Transmission_Control_Protocol
