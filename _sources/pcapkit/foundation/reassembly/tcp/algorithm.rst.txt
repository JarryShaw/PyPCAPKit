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
