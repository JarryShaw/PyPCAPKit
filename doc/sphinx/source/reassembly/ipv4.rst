IPv4 Datagram Reassembly
========================

:mod:`pcapkit.foundation.reassembly.ipv4` contains
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4_Reassembly`
only, which reconstructs fragmented IPv4 packets back to
origin. Please refer to :doc:`ip` for more information.

Data Structure
--------------

.. glossary::

   ipv4.packet
       Data structure for **IPv4 datagram reassembly**
       (:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly`)
       is as following:

   .. code-block:: python

      packet_dict = dict(
        bufid = tuple(
            ipv4.src,                   # source IP address
            ipv4.dst,                   # destination IP address
            ipv4.id,                    # identification
            ipv4.proto,                 # payload protocol type
        ),
        num = frame.number,             # original packet range number
        fo = ipv4.frag_offset,          # fragment offset
        ihl = ipv4.hdr_len,             # internet header length
        mf = ipv4.flags.mf,             # more fragment flag
        tl = ipv4.len,                  # total length, header includes
        header = ipv4.header,           # raw bytearray type header
        payload = ipv4.payload,         # raw bytearray type payload
      )

   ipv4.datagram
      Data structure for **reassembled IPv4 datagram** (element from
      :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.datagram` *tuple*)
      is as following:

   .. code-block:: python

      (tuple) datagram
       |--> (dict) data
       |     |--> 'NotImplemented' : (bool) True --> implemented
       |     |--> 'index' : (tuple) packet numbers
       |     |               |--> (int) original packet range number
       |     |--> 'packet' : (Optional[bytes]) reassembled IPv4 packet
       |--> (dict) data
       |     |--> 'NotImplemented' : (bool) False --> not implemented
       |     |--> 'index' : (tuple) packet numbers
       |     |               |--> (int) original packet range number
       |     |--> 'header' : (Optional[bytes]) IPv4 header
       |     |--> 'payload' : (Optional[tuple]) partially reassembled IPv4 payload
       |                       |--> (Optional[bytes]) IPv4 payload fragment
       |--> (dict) data ...

   ipv4.buffer
      Data structure for internal buffering when performing reassembly algorithms
      (:attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._buffer`) is as following:

      .. code-block:: python

         (dict) buffer --> memory buffer for reassembly
          |--> (tuple) BUFID : (dict)
          |     |--> ipv4.src       |
          |     |--> ipc6.dst       |
          |     |--> ipv4.label     |
          |     |--> ipv4_frag.next |
          |                         |--> 'TDL' : (int) total data length
          |                         |--> RCVBT : (bytearray) fragment received bit table
          |                         |             |--> (bytes) b'\x00' -> not received
          |                         |             |--> (bytes) b'\x01' -> received
          |                         |             |--> (bytes) ...
          |                         |--> 'index' : (list) list of reassembled packets
          |                         |               |--> (int) packet range number
          |                         |--> 'header' : (bytearray) header buffer
          |                         |--> 'datagram' : (bytearray) data buffer, holes set to b'\x00'
          |--> (tuple) BUFID ...

Implementation
--------------

.. automodule:: pcapkit.foundation.reassembly.ipv4
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:
