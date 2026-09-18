=======================
TCP Datagram Reassembly
=======================

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which reconstructs fragmented TCP packets back to origin.

.. autoclass:: pcapkit.foundation.reassembly.tcp.TCP
   :no-members:
   :show-inheritance:

   .. automethod:: reassembly
   .. automethod:: submit

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

Algorithm
=========

.. seealso::

   This algorithm is an adaptation of the algorithm described in
   :rfc:`815`.

+-------------+---------------------------+
| Attribute   | Definition                |
+=============+===========================+
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
| ``HDL``     | Hole Descriptor List      |
+-------------+---------------------------+
| ``ISN``     | Initial Sequence Number   |
+-------------+---------------------------+
| ``PSN``     | Payload Sequence Number   |
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
      BUFID <- src|srcport|dst|dstport;

      /* a SYN occupies a sequence number of its own, so payload sent by
         or after it starts one octet later than the segment's DSN */
      PSN <- DSN + 1 IF (SYN is true) ELSE DSN;

      IF (SYN is true) {
         IF (buffer with BUFID is allocated) {
            flush all reassembly for this BUFID;
            submit datagram to next step;
         }
      }

      IF (no buffer with BUFID is allocated) {
         allocate reassembly resources with BUFID;
         ISN <- PSN;
         put data from fragment into data buffer with BUFID
            [from octet fragment.first to octet fragment.last];
         HDL <- [one hole from PSN + fragment.len to infinity];
      } ELSE {
         put data from fragment into data buffer with BUFID
            [from octet fragment.first to octet fragment.last];

         /* a segment with no payload fills no hole, and its "last" lies
            one below its "first", so it is not run through the algorithm */
         IF (fragment.len > 0) {
            update HDL;
         }
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

         IF (fragment.first > hole.last) CONTINUE.
         IF (fragment.last < hole.first) CONTINUE.

         delete the current entry from HDL;

         IF (fragment.first > hole.first) {
            create new entry "new_hole" in HDL;
            new_hole.first <- hole.first;
            new_hole.last <- fragment.first - 1;
         }

         IF (fragment.last < hole.last AND FIN is false AND RST is false) {
            create new entry "new_hole" in HDL;
            new_hole.first <- fragment.last + 1;
            new_hole.last <- hole.last;
         }

         BREAK.
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
6. If ``fragment.last`` is less than ``hole.last`` and neither ``FIN``
   nor ``RST`` is set -- TCP has no *more fragments* flag, so the
   termination flags take its place -- then create a new hole
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
            first = tcp.seq,                # first sequence number of payload
            last = tcp.seq + tcp.raw_len - 1,
                                            # last sequence number of payload
            header = tcp.packet.header,     # raw bytes type header
            payload = tcp.raw,              # raw bytearray type payload
            timestamp = float(
                frame.time_epoch),          # capture timestamp
          )

       Both ``first`` and ``last`` are absolute TCP sequence numbers and
       both are **inclusive**, so a segment carrying no payload at all has
       ``last`` one below ``first``.

   reasm.tcp.datagram
       Data structure for **reassembled TCP datagram** (element from
       :attr:`TCP.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) datagram
           |--> (Info) data
           |     |--> 'completed' : (Completion) COMPLETE --> reassembled in whole
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
           |     |--> 'conflict' : (tuple) sequence ranges on which two segments disagreed
           |     |                  |--> (tuple) (first, last), absolute and inclusive
           |     |                  |--> ...
           |--> (Info) data
           |     |--> 'completed' : (Completion) PARTIAL or TIMEOUT --> incomplete
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
           |     |--> 'conflict' : (tuple) sequence ranges on which two segments disagreed
           |     |                  |--> (tuple) (first, last), absolute and inclusive
           |     |                  |--> ...
           |--> (Info) data ...

       ``completed`` and ``conflict`` are independent signals: a datagram can
       be :attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`
       and still carry a non-empty ``conflict`` -- the resolution of a
       conflicting overlap is first-write-wins (:rfc:`9293#section-3.10`), so
       it never leaves a hole, and a contested range that was later filled in
       around does not stop the datagram from completing. ``conflict`` is
       what lets a caller tell a clean stream from a contested one, now that
       ``completed`` alone no longer can.

   reasm.tcp.buffer
       Data structure for internal buffering when performing reassembly algorithms
       (:attr:`TCP._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is as following:

       .. code-block:: text

          (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src      |
           |       |--> tcp.srcport |
           |       |--> ip.dst      |
           |       |--> tcp.dstport |
           |                        |--> 'hdl' : (list) hole descriptor list
           |                        |             |--> (Info) hole --> hole descriptor
           |                        |                   |--> "first" --> (int) sequence number of the
           |                        |                   |                     first missing octet
           |                        |                   |--> "last" --> (int) sequence number of the
           |                        |                                        last missing octet, inclusive
           |                        |--> 'hdr' : (bytes) initial TCP header
           |                        |--> 'ack' : (dict) ACK list
           |                                      |--> (int) ACK : (dict)
           |                                      |                 |--> 'ind' : (list) list of reassembled packets
           |                                      |                 |             |--> (int) packet range number
           |                                      |                 |--> 'isn' : (int) sequence number of the octet
           |                                      |                 |                  held in raw[0]
           |                                      |                 |--> 'len' : (int) length of payload buffer
           |                                      |                 |--> 'raw' : (bytearray) reassembled payload,
           |                                      |                                          holes set to b'\x00'
           |                                      |                 |--> 'conflict' : (list) sequence ranges on which
           |                                      |                 |                  an arriving segment disagreed
           |                                      |                 |                  with bytes already in 'raw'
           |                                      |                 |                  |--> (tuple) (first, last),
           |                                      |                 |                               absolute and
           |                                      |                 |                               inclusive
           |                                      |                 |                  |--> ...
           |                                      |--> (int) ACK ...
           |                                      |--> ...
           |                        |--> 'timestamp' : (float) capture timestamp of the
           |                                                   first segment buffered
           |--> (tuple) BUFID ...

       .. note::

          TCP reassembly has **no** timeout by default: no specification gives
          stream reassembly a deadline the way :rfc:`1122#section-3.3.2` and
          :rfc:`8200#section-4.5` give IP fragmentation one, and an idle
          connection is ordinary rather than pathological. ``timestamp`` is
          recorded regardless, so passing ``timeout`` to
          :class:`~pcapkit.foundation.reassembly.tcp.TCP` enables the same
          eviction the IP reassemblers use -- see
          :attr:`TCP.__timeout__ <pcapkit.foundation.reassembly.tcp.TCP.__timeout__>`.

       The hole descriptor list is kept in **absolute TCP sequence numbers**,
       once per ``BUFID``, whereas each ACK's payload buffer is indexed from
       its own ``isn`` -- ``raw[n]`` holds the octet with sequence number
       ``isn + n``, and ``isn`` is revised downwards whenever a segment turns
       up below the data already buffered, so it is not necessarily the
       connection's own initial sequence number.
       :meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` is the
       one place that converts between the two.

Data Models
===========

.. module:: pcapkit.foundation.reassembly.data.tcp
.. currentmodule:: pcapkit.foundation.reassembly.tcp

.. autodata:: pcapkit.foundation.reassembly.data.tcp.BufferID

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Packet
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Datagram
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.HoleDescriptor
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Fragment
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.reassembly.data.tcp.BufferID

.. autoclass:: pcapkit.foundation.reassembly.data.tcp.Buffer
   :members:
   :show-inheritance:

Type Variables
==============

.. data:: pcapkit.foundation.reassembly.data.tcp._AT
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

.. data:: pcapkit.foundation.reassembly.data.tcp.BufferID
   :type: typing.Tuple[_AT, int, _AT, int]

   Buffer ID data structure.
