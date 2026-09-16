IPv4 Datagram Reassembly
========================

.. module:: pcapkit.foundation.reassembly.ipv4

:mod:`pcapkit.foundation.reassembly.ipv4` contains
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4`
only, which reconstructs fragmented IPv4 packets back to
origin. Please refer to :doc:`ip` for more information.

.. autoclass:: pcapkit.foundation.reassembly.ipv4.IPv4
   :no-members:
   :show-inheritance:

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

Terminology
-----------

.. glossary::

   reasm.ipv4.packet
       Data structure for **IPv4 datagram reassembly**
       (:meth:`IPv4.reassembly <pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly>`)
       is as following, with ``ipv4`` the protocol instance
       (``frame['IPv4']``) and ``ipv4_info`` its :attr:`~pcapkit.protocols.protocol.ProtocolBase.info`
       -- the header fields come off the latter, the raw octets off the former:

       .. code-block:: python

          packet_dict = dict(
            bufid = (
                ipv4_info.src,              # source IP address
                ipv4_info.dst,              # destination IP address
                ipv4_info.id,               # identification
                ipv4_info.protocol,         # payload protocol type
            ),
            num = frame.info.number,        # original packet range number
            fo = ipv4_info.offset,          # fragment offset, in octets
            ihl = ipv4_info.hdr_len,        # internet header length
            mf = ipv4_info.flags.mf,        # more fragment flag
            tl = ipv4_info.len,             # total length, header includes
            header = ipv4.packet.header,    # raw bytes type header
            payload = bytearray(
                ipv4.packet.payload),       # raw bytearray type payload
          )

   reasm.ipv4.datagram
       Data structure for **reassembled IPv4 datagram** (element from
       :attr:`IPv4.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) datagram
           |--> (Info) data
           |     |--> 'completed' : (bool) True --> implemented
           |     |--> 'id' : (Info) original packet identifier
           |     |            |--> 'src' --> (IPv4Address) ipv4.src
           |     |            |--> 'dst' --> (IPv4Address) ipv4.dst
           |     |            |--> 'id' --> (int) ipv4.id
           |     |            |--> 'proto' --> (TransType) ipv4.protocol
           |     |--> 'index' : (tuple) packet numbers
           |     |               |--> (int) original packet range number
           |     |--> 'header' : (bytes) IPv4 header
           |     |--> 'payload' : (bytes) reassembled IPv4 payload
           |     |--> 'packet' : (Protocol) parsed reassembled payload
           |--> (Info) data
           |     |--> 'completed' : (bool) False --> not implemented
           |     |--> 'id' : (Info) original packet identifier
           |     |            |--> 'src' --> (IPv4Address) ipv4.src
           |     |            |--> 'dst' --> (IPv4Address) ipv4.dst
           |     |            |--> 'id' --> (int) ipv4.id
           |     |            |--> 'proto' --> (TransType) ipv4.protocol
           |     |--> 'index' : (tuple) packet numbers
           |     |               |--> (int) original packet range number
           |     |--> 'header' : (bytes) IPv4 header
           |     |--> 'payload' : (tuple) partially reassembled IPv4 payload
           |     |                 |--> (bytes) IPv4 payload fragment
           |     |                 |--> ...
           |     |--> 'packet' : (None)
           |--> (Info) data ...

   reasm.ipv4.buffer
       Data structure for internal buffering when performing reassembly algorithms
       (:attr:`IPv4._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is as following:

       .. code-block:: text

          (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |     |--> ipv4.src       |
           |     |--> ipv4.dst       |
           |     |--> ipv4.id        |
           |     |--> ipv4.protocol  |
           |                         |--> 'TDL' : (int) total data length
           |                         |--> 'RCVBT' : (bytearray) fragment received bit table
           |                         |               |--> (bytes) b'\\x00' -> not received
           |                         |               |--> (bytes) b'\\x01' -> received
           |                         |               |--> (bytes) ...
           |                         |--> 'index' : (list) list of reassembled packets
           |                         |               |--> (int) packet range number
           |                         |--> 'header' : (bytes) header buffer
           |                         |--> 'datagram' : (bytearray) data buffer, holes set to b'\\x00'
           |--> (tuple) BUFID ...
