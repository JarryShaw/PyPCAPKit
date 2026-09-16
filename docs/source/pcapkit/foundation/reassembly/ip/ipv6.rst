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
       is as following:

       .. code-block:: python

          packet_dict = dict(
            bufid = tuple(
                ipv6.src,                   # source IP address
                ipv6.dst,                   # destination IP address
                ipv6_frag.id,               # identification
                ipv6_frag.next,             # next header field in IPv6 Fragment Header
            ),
            num = frame.number,             # original packet range number
            fo = ipv6_frag.offset,          # fragment offset, in octets
            ihl = ipv6.hdr_len,             # header length, only headers before IPv6-Frag
            mf = ipv6_frag.mf,              # more fragment flag
            tl = ipv6.hdr_len
                 + ipv6.raw_len,            # total length, header includes
            header = ipv6.header,           # raw bytes type header before IPv6-Frag
            payload = ipv6.payload,         # raw bytearray type payload after IPv6-Frag
          )

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
