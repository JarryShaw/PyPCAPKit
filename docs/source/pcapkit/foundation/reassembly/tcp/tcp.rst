Implementation
==============

.. module:: pcapkit.foundation.reassembly.tcp

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which reconstructs fragmented TCP packets back to origin.

.. autoclass:: pcapkit.foundation.reassembly.tcp.TCP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: protocol

   .. automethod:: reassembly
   .. automethod:: submit

Terminology
-----------

.. glossary::

   tcp.packet
       Data structure for **TCP datagram reassembly**
       (:meth:`TCP.reassembly <pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly>`)
       is as following:

       .. code-block:: python

          packet_dict = Info(
            bufid = tuple(
                ip.src,                     # source IP address
                tcp.srcport,                # source port
                ip.dst,                     # destination IP address
                tcp.dstport,                # destination port
            ),
            dsn = tcp.seq,                  # data sequence number
            ack = tcp.ack,                  # acknowledgement number
            num = frame.number,             # original packet range number
            syn = tcp.flags.syn,            # synchronise flag
            fin = tcp.flags.fin,            # finish flag
            rst = tcp.flags.rst,            # reset connection flag
            len = tcp.raw_len,              # payload length, header excludes
            first = tcp.seq,                # this sequence number
            last = tcp.seq + tcp.raw_len,   # next (wanted) sequence number
            header = tcp.packet.header,     # raw bytes type header
            payload = tcp.raw,              # raw bytearray type payload
          )

   tcp.datagram
       Data structure for **reassembled TCP datagram** (element from
       :attr:`TCP.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) datagram
           |--> (Info) data
           |     |--> 'completed' : (bool) True --> implemented
           |     |--> 'id' : (Info) original packet identifier
           |     |            |--> 'src' --> (tuple)
           |     |            |               |--> (IPv4Address) ip.src
           |     |            |               |--> (int) tcp.srcport
           |     |            |--> 'dst' --> (tuple)
           |     |            |               |--> (IPv4Address) ip.dst
           |     |            |               |--> (int) tcp.dstport
           |     |            |--> 'ack' --> (int) original packet ACK number
           |     |--> 'index' : (tuple) packet numbers
           |     |               |--> (int) original packet range number
           |     |               |--> ...
           |     |--> 'header' : (bytes) initial TCP header
           |     |--> 'payload' : (bytes) reassembled payload
           |     |--> 'packet' : (Protocol) parsed reassembled payload
           |--> (Info) data
           |     |--> 'completed' : (bool) False --> not implemented
           |     |--> 'id' : (Info) original packet identifier
           |     |            |--> 'src' --> (tuple)
           |     |            |               |--> (IPv4Address) ip.src
           |     |            |               |--> (int) tcp.srcport
           |     |            |--> 'dst' --> (tuple)
           |     |            |               |--> (IPv4Address) ip.dst
           |     |            |               |--> (int) tcp.dstport
           |     |            |--> 'ack' --> (int) original packet ACK number
           |     |--> 'index' : (tuple) packet numbers
           |     |               |--> (int) original packet range number
           |     |               |--> ...
           |     |--> 'header' : (bytes) initial TCP header
           |     |--> 'payload' : (tuple) partially reassembled payload
           |     |                 |--> (bytes) payload fragment
           |     |                 |--> ...
           |     |--> 'packet' : (None) not implemented
           |--> (Info) data ...

   tcp.buffer
       Data structure for internal buffering when performing reassembly algorithms
       (:attr:`TCP._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is as following:

       .. code-block:: text

          (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src      |
           |       |--> ip.dst      |
           |       |--> tcp.srcport |
           |       |--> tcp.dstport |
           |                        |--> 'hdl' : (list) hole descriptor list
           |                        |             |--> (Info) hole --> hole descriptor
           |                        |                   |--> "first" --> (int) start of hole
           |                        |                   |--> "last" --> (int) stop of hole
           |                        |--> 'hdr' : (bytes) initial TCP header
           |                        |--> 'ack' : (dict) ACK list
           |                                      |--> (int) ACK : (dict)
           |                                      |                 |--> 'ind' : (list) list of reassembled packets
           |                                      |                 |             |--> (int) packet range number
           |                                      |                 |--> 'isn' : (int) ISN of payload buffer
           |                                      |                 |--> 'len' : (int) length of payload buffer
           |                                      |                 |--> 'raw' : (bytearray) reassembled payload,
           |                                      |                                          holes set to b'\x00'
           |                                      |--> (int) ACK ...
           |                                      |--> ...
           |--> (tuple) BUFID ...

Data Structures
---------------

.. autoclass:: pcapkit.foundation.reassembly.tcp.Packet(bufid, dsn, ack, num, syn, fin, rst, len, first, last, header, payload)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: bufid
   .. autoattribute:: dsn
   .. autoattribute:: ack
   .. autoattribute:: num
   .. autoattribute:: syn
   .. autoattribute:: fin
   .. autoattribute:: rst
   .. autoattribute:: len
   .. autoattribute:: first
   .. autoattribute:: last
   .. autoattribute:: header
   .. autoattribute:: payload

.. autoclass:: pcapkit.foundation.reassembly.tcp.DatagramID(src, dst, ack)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: src
   .. autoattribute:: dst
   .. autoattribute:: ack

.. autoclass:: pcapkit.foundation.reassembly.tcp.Datagram(completed, id, index, header, payload, packet)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: completed
   .. autoattribute:: id
   .. autoattribute:: index
   .. autoattribute:: header
   .. autoattribute:: payload
   .. autoattribute:: packet

.. autoclass:: pcapkit.foundation.reassembly.tcp.HoleDiscriptor(fisrt, last)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: first
   .. autoattribute:: last

.. autoclass:: pcapkit.foundation.reassembly.tcp.Fragment(ind, isn, len, raw)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ind
   .. autoattribute:: isn
   .. autoattribute:: len
   .. autoattribute:: raw

.. autoclass:: pcapkit.foundation.reassembly.tcp.Buffer(hdl, hdr, ack)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hdl
   .. autoattribute:: hdr
   .. autoattribute:: ack
