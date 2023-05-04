TCP - Transmission Control Protocol
===================================

.. module:: pcapkit.protocols.transport.tcp

:mod:`pcapkit.protocols.transport.tcp` contains
:class:`~pcapkit.protocols.transport.tcp.TCP` only,
which implements extractor for Transmission Control
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
  12        100                             Reserved (must be ``\x00``)
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
  20        160   ``tcp.opt``               TCP Options (if data offset > 5)
======= ========= ========================= =======================================

.. autoclass:: pcapkit.protocols.transport.tcp.TCP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

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
   .. autoattribute:: __option__
      :no-value:
   .. autoattribute:: __mp_option__
      :no-value:

   .. automethod:: __index__

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.transport.tcp.Flags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.transport.tcp

.. autoclass:: pcapkit.protocols.schema.transport.tcp.TCP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.Flags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.UnassignedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.EndOfOptionList
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.NoOperation
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MaximumSegmentSize
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.WindowScale
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.SACKPermitted
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.SACK
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.Echo
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.EchoReply
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.Timestamp
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.PartialOrderConnectionPermitted
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.PartialOrderConnectionProfile
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.CC
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.CCNew
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.CCEcho
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.AlternateChecksumRequest
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.AlternateChecksumData(kind, length, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MD5Signature(kind, length, digest)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: digest

.. autoclass:: pcapkit.protocols.schema.transport.tcp.QuickStartResponse
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.UserTimeout
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.Authentication
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.FastOpenCookie
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPUnknown
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPCapable
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPJoin
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPJoinSYN
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPJoinSYNACK
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPJoinACK
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPDSS
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPAddAddress
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPRemoveAddress
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPPriority
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPFallback
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPFastclose
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.transport.tcp.OffsetFlag
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.Flags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.POCProfile
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.QuickStartFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.QuickStartNonce
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.TimeoutInfo
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtypeTest
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtypeUnknown
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtypeCapable
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPCapableFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtypeJoin
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtype
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPDSSFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtypeAddAddress
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.transport.tcp.MPTCPSubtypePriority
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.transport.tcp.mptcp_data_selector
.. autofunction:: pcapkit.protocols.schema.transport.tcp.mptcp_add_address_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.transport.tcp

.. autoclass:: pcapkit.protocols.data.transport.tcp.TCP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.Flags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.UnassignedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.EndOfOptionList
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.NoOperation
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MaximumSegmentSize
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.WindowScale
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.SACKPermitted
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.SACK
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.Echo
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.EchoReply
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.Timestamp
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.PartialOrderConnectionPermitted
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.PartialOrderConnectionProfile
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.CC
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.CCNew
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.CCEcho
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.AlternateChecksumRequest
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.AlternateChecksumData(kind, length, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.transport.tcp.MD5Signature(kind, length, digest)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: digest

.. autoclass:: pcapkit.protocols.data.transport.tcp.QuickStartResponse
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.UserTimeout
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.Authentication
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.FastOpenCookie
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPUnknown
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPCapable
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoin
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoinSYN
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoinSYNACK
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoinACK
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPDSS
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPAddAddress
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPRemoveAddress
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPPriority
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPFallback
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPFastclose
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Transmission_Control_Protocol
