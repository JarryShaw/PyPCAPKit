=======================
TCP Datagram Reassembly
=======================

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which reconstructs fragmented TCP packets back to origin.

.. autoclass:: pcapkit.foundation.reassembly.tcp.TCP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: protocol

   .. automethod:: reassembly
   .. automethod:: submit

Algorithm
=========

.. seealso::

   This algorithm is an adaptation of the algorithm described in
   :rfc:`815`.

+-------------+---------------------------+
| ``DSN``     | Data Sequence Number      |
+-------------+---------------------------+
| ``ACK``     | TCP Acknowledgement       |
+-------------+---------------------------+
| ``SYN``     | TCP Synchronisation Flag  |
+-------------+---------------------------+
| ``FIN``     | TCP Finish Flag           |
+-------------+---------------------------+
| ``RST``     | TCP Reset Connection Flag |
+-------------+---------------------------+
| ``BUFID``   | Buffer Identifier         |
+-------------+---------------------------+
| ``HDL``     | Hole Discriptor List      |
+-------------+---------------------------+
| ``ISN``     | Initial Sequence Number   |
+-------------+---------------------------+
| ``src``     | source IP                 |
+-------------+---------------------------+
| ``dst``     | destination IP            |
+-------------+---------------------------+
| ``srcport`` | source TCP port           |
+-------------+---------------------------+
| ``dstport`` | destination TCP port      |
+-------------+---------------------------+

.. code-block:: text

   DO {
      BUFID <- src|dst|srcport|dstport|ACK;
      IF (SYN is true) {
         IF (buffer with BUFID is allocated) {
            flush all reassembly for this BUFID;
            submit datagram to next step;
         }
      }

      IF (no buffer with BUFID is allocated) {
         allocate reassembly resources with BUFID;
         ISN <- DSN;
         put data from fragment into data buffer with BUFID
            [from octet fragment.first to octet fragment.last];
         update HDL;
      }

      IF (FIN is true or RST is true) {
         submit datagram to next step;
         free all reassembly resources for this BUFID;
         BREAK.
      }
   } give up until (next fragment);

   update HDL: {
      DO {
         select the next hole descriptor from HDL;

         IF (fragment.first >= hole.first) CONTINUE.
         IF (fragment.last <= hole.first) CONTINUE.

         delete the current entry from HDL;

         IF (fragment.first >= hole.first) {
            create new entry "new_hole" in HDL;
            new_hole.first <- hole.first;
            new_hole.last <- fragment.first - 1;
            BREAK.
         }

         IF (fragment.last <= hole.last) {
            create new entry "new_hole" in HDL;
            new_hole.first <- fragment.last + 1;
            new_hole.last <- hole.last;
            BREAK.
         }
      } give up until (no entry from HDL)
   }

The following algorithm implement is based on **IP Datagram
Reassembly Algorithm** introduced in :rfc:`815`. It described an
algorithm dealing with ``RCVBT`` (fragment received bit table)
appeared in :rfc:`791`. And here is the process:

1. Select the next hole descriptor from the hole descriptor
   list. If there are no more entries, go to step eight.
2. If ``fragment.first`` is greater than ``hole.last``, go to step one.
3. If ``fragment.last`` is less than ``hole.first``, go to step one.
4. Delete the current entry from the hole descriptor list.
5. If ``fragment.first`` is greater than ``hole.first``, then create a
   new hole descriptor ``new_hole`` with ``new_hole.first`` equal to
   ``hole.first``, and ``new_hole.last`` equal to ``fragment.first``
   minus one (``-1``).
6. If ``fragment.last`` is less than ``hole.last`` and
   ``fragment.more_fragments`` is ``true``, then create a new hole
   descriptor ``new_hole``, with ``new_hole.first`` equal to
   ``fragment.last`` plus one (``+1``) and ``new_hole.last`` equal to
   ``hole.last``.
7. Go to step one.
8. If the hole descriptor list is now empty, the datagram is now
   complete. Pass it on to the higher level protocol processor
   for further handling. Otherwise, return.

Terminology
===========

.. glossary::

   reasm.tcp.packet
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

   reasm.tcp.datagram
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

   reasm.tcp.buffer
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

Data Models
===========

.. module:: pcapkit.foundation.reassembly.data.tcp

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Packet
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.DatagramID
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Datagram
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.HoleDiscriptor
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Fragment
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autodata:: pcapkit.foundation.reassembly.data.tcp.BufferID

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Buffer
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
