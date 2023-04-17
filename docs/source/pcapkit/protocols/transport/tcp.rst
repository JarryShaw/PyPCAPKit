TCP - Transmission Control Protocol
===================================

.. module:: pcapkit.protocols.transport.tcp
.. module:: pcapkit.protocols.data.transport.tcp

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

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.transport.tcp.TCP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_option
   .. automethod:: register_mp_option

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

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __option__
      :no-value:
   .. autoattribute:: __mp_option__
      :no-value:

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.transport.tcp.TCP(srcport, dstport, seq, ack, hdr_len, flags, window_size, checksum, urgent_pointer)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: srcport
   .. autoattribute:: dstport
   .. autoattribute:: seq
   .. autoattribute:: ack
   .. autoattribute:: hdr_len
   .. autoattribute:: flags
   .. autoattribute:: window_size
   .. autoattribute:: checksum
   .. autoattribute:: urgent_pointer

   .. autoattribute:: options

.. autoclass:: pcapkit.protocols.data.transport.tcp.Flags(ns, cwr, ece, urg, ack, psh, rst, syn, fin)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ns
   .. autoattribute:: cwr
   .. autoattribute:: ece
   .. autoattribute:: urg
   .. autoattribute:: ack
   .. autoattribute:: psh
   .. autoattribute:: rst
   .. autoattribute:: syn
   .. autoattribute:: fin

.. autoclass:: pcapkit.protocols.data.transport.tcp.Option(kind, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: kind
   .. autoattribute:: length

.. autoclass:: pcapkit.protocols.data.transport.tcp.UnassignedOption(kind, length, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.transport.tcp.EndOfOptionList(kind, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.NoOperation(kind, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MaximumSegmentSize(kind, length, mss)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: mss

.. autoclass:: pcapkit.protocols.data.transport.tcp.WindowScale(kind, length, shift)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: shift

.. autoclass:: pcapkit.protocols.data.transport.tcp.SACKPermitted(kind, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.SACK(kind, length, sack)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: sack

.. autoclass:: pcapkit.protocols.data.transport.tcp.Echo(kind, length, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.transport.tcp.EchoReply(kind, length, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.transport.tcp.Timestamp(kind, length, timestamp, echo)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: timestamp
   .. autoattribute:: echo

.. autoclass:: pcapkit.protocols.data.transport.tcp.PartialOrderConnectionPermitted(kind, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.PartialOrderConnectionProfile(kind, length, start, end)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: start
   .. autoattribute:: end

.. autoclass:: pcapkit.protocols.data.transport.tcp.CC(kind, length, cc)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cc

.. autoclass:: pcapkit.protocols.data.transport.tcp.CCNew(kind, length, cc)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cc

.. autoclass:: pcapkit.protocols.data.transport.tcp.CCEcho(kind, length, cc)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cc

.. autoclass:: pcapkit.protocols.data.transport.tcp.AlternateChecksumRequest(kind, length, chksum)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: chksum

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

.. autoclass:: pcapkit.protocols.data.transport.tcp.QuickStartResponse(kind, length, req_rate, ttl_diff, nonce)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: req_rate
   .. autoattribute:: ttl_diff
   .. autoattribute:: nonce

.. autoclass:: pcapkit.protocols.data.transport.tcp.UserTimeout(kind, length, timeout)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: timeout

.. autoclass:: pcapkit.protocols.data.transport.tcp.Authentication(kind, length, key_id, next_key_id, mac)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: key_id
   .. autoattribute:: next_key_id
   .. autoattribute:: mac

.. autoclass:: pcapkit.protocols.data.transport.tcp.FastOpenCookie(kind, length, cookie)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cookie

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCP(kind, length, subtype)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: subtype

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPUnknown(kind, length, subtype, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPCapable(kind, length, subtype, version, flags, skey, rkey)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: version
   .. autoattribute:: flags
   .. autoattribute:: skey
   .. autoattribute:: rkey

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPCapableFlag(req, ext, hsa)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: req
   .. autoattribute:: ext
   .. autoattribute:: hsa

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoin(kind, length, subtype)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoinSYN(kind, length, subtype, connection, backup, addr_id, token, nonce)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: connection
   .. autoattribute:: backup
   .. autoattribute:: addr_id
   .. autoattribute:: token
   .. autoattribute:: nonce

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoinSYNACK(kind, length, subtype, connection, backup, addr_id, hmac, nonce)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: connection
   .. autoattribute:: backup
   .. autoattribute:: addr_id
   .. autoattribute:: hmac
   .. autoattribute:: nonce

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPJoinACK(kind, length, subtype, connection, hmac)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: connection
   .. autoattribute:: hmac

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPDSS(kind, length, subtype, flags, ack, dsn, ssn, dl_len, checksum)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: ack
   .. autoattribute:: dsn
   .. autoattribute:: ssn
   .. autoattribute:: dl_len
   .. autoattribute:: checksum

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPDSSFlag(data_fin, dsn_oct, data_pre, ack_oct, ack_pre)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data_fin
   .. autoattribute:: dsn_oct
   .. autoattribute:: data_pre
   .. autoattribute:: ack_oct
   .. autoattribute:: ack_pre

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPAddAddress(kind, length, subtype, version, addr_id, addr, port)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: version
   .. autoattribute:: addr_id
   .. autoattribute:: addr
   .. autoattribute:: port

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPRemoveAddress(kind, length, subtype, addr_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: addr_id

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPPriority(kind, length, subtype, backup, addr_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: backup
   .. autoattribute:: addr_id

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPFallback(kind, length, subtype, dsn)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: dsn

.. autoclass:: pcapkit.protocols.data.transport.tcp.MPTCPFastclose(kind, length, subtype, rkey)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: rkey


.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Transmission_Control_Protocol
