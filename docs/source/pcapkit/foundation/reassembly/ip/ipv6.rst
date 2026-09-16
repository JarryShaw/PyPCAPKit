IPv6 Datagram Reassembly
========================

.. module:: pcapkit.foundation.reassembly.ipv6

:mod:`pcapkit.foundation.reassembly.ipv6` contains
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6`
only, which reconstructs fragmented IPv6 packets back to
origin. Please refer to :doc:`ip` for more information.

.. autoclass:: pcapkit.foundation.reassembly.ipv6.IPv6
   :no-members:
   :show-inheritance:

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

Terminology
-----------

.. glossary::

   reasm.ipv6.packet
       Data structure for **IPv6 datagram reassembly**
       (:meth:`IPv6.reassembly <pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly>`)
       is as following, with ``ipv6_info`` the IPv6
       :attr:`~pcapkit.protocols.protocol.ProtocolBase.info` and
       ``ipv6_frag_info`` the Fragment header's:

       .. code-block:: python

          packet_dict = dict(
            bufid = (
                ipv6_info.src,              # source IP address
                ipv6_info.dst,              # destination IP address
                ipv6_frag_info.id,          # identification
                ipv6_frag_info.next,        # next header field in IPv6 Fragment Header
            ),
            num = frame.info.number,        # original packet range number
            fo = ipv6_frag_info.offset,     # fragment offset, in octets
            ihl = ipv6_info.hdr_len,        # header length, IPv6-Frag included
            mf = ipv6_frag_info.mf,         # more fragment flag
            tl = ipv6_info.hdr_len
                 + ipv6_info.raw_len,       # total length, header includes
            header = ipv6_info.fragment
                     .header,               # raw bytes type header, IPv6-Frag included
            payload = bytearray(
                ipv6_info.fragment
                .payload),                  # raw bytearray type payload after IPv6-Frag
          )

       .. warning::

          ``ihl`` and ``header`` here **include** the 8-octet Fragment header,
          because :attr:`IPv6.hdr_len <pcapkit.protocols.data.internet.ipv6.IPv6.hdr_len>`
          counts every extension header it has walked, the Fragment one included.
          The ``dpkt`` and ``scapy`` adapters stop short of it and report 40 where
          this one reports 48 for the same packet, so the value is not comparable
          across engines -- and :rfc:`8200#section-4.5` says the Fragment header
          is not present in a reassembled packet at all. Tracked as #415; expect
          this line to change when that is fixed.

       .. note::

          The reassembly key is the Fragment header's *Identification*
          (:rfc:`8200#section-4.5`), not the IPv6 header's *Flow Label*. The
          label is optional and routinely zero, so keying on it collapses
          every datagram between one address pair into a single buffer and
          interleaves their fragments.

   reasm.ipv6.datagram
       Data structure for **reassembled IPv6 datagram** (element from
       :attr:`IPv6.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) datagram
           |--> (Info) data
           |     |--> 'completed' : (bool) True --> implemented
           |     |--> 'id' : (Info) original packet identifier
           |     |            |--> 'src' --> (IPv6Address) ipv6.src
           |     |            |--> 'dst' --> (IPv6Address) ipv6.dst
           |     |            |--> 'id' --> (int) ipv6_frag.id
           |     |            |--> 'proto' --> (TransType) ipv6_frag.next
           |     |--> 'index' : (tuple) packet numbers
           |     |               |--> (int) original packet range number
           |     |--> 'header' : (bytes) header before IPv6-Frag
           |     |--> 'payload' : (bytes) reassembled IPv6 payload
           |     |--> 'packet' : (Protocol) parsed reassembled payload
           |--> (Info) data
           |     |--> 'completed' : (bool) False --> not implemented
           |     |--> 'id' : (Info) original packet identifier
           |     |            |--> 'src' --> (IPv6Address) ipv6.src
           |     |            |--> 'dst' --> (IPv6Address) ipv6.dst
           |     |            |--> 'id' --> (int) ipv6_frag.id
           |     |            |--> 'proto' --> (TransType) ipv6_frag.next
           |     |--> 'index' : (tuple) packet numbers
           |     |               |--> (int) original packet range number
           |     |--> 'header' : (bytes) header before IPv6-Frag
           |     |--> 'payload' : (tuple) partially reassembled IPv6 payload
           |     |                 |--> (bytes) IPv6 payload fragment
           |     |                 |--> ...
           |     |--> 'packet' : (None)
           |--> (Info) data ...

   reasm.ipv6.buffer
       Data structure for internal buffering when performing reassembly algorithms
       (:attr:`IPv6._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is as following:

       .. code-block:: text

          (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |     |--> ipv6.src       |
           |     |--> ipv6.dst       |
           |     |--> ipv6_frag.id   |
           |     |--> ipv6_frag.next |
           |                         |--> 'TDL' : (int) total data length
           |                         |--> RCVBT : (bytearray) fragment received bit table
           |                         |             |--> (bytes) b'\\x00' -> not received
           |                         |             |--> (bytes) b'\\x01' -> received
           |                         |             |--> (bytes) ...
           |                         |--> 'index' : (list) list of reassembled packets
           |                         |               |--> (int) packet range number
           |                         |--> 'header' : (bytes) header buffer
           |                         |--> 'datagram' : (bytearray) data buffer, holes set to b'\\x00'
           |--> (tuple) BUFID ...
