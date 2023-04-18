======================
IP Datagram Reassembly
======================

The following algorithm implement is based on IP
reassembly procedure introduced in :rfc:`791`, using
``RCVBT`` (fragment receivedbit table). Though another
algorithm is explained in :rfc:`815`, replacing ``RCVBT``,
however, this implement still used the elder one.

.. toctree::
   :maxdepth: 2

   ip
   ipv4
   ipv6

Algorithm
=========

.. seealso::

   The algorithm is described in :rfc:`791`.

+-----------+-----------------------------+
| ``FO``    | Fragment Offset             |
+-----------+-----------------------------+
| ``IHL``   | Internet Header Length      |
+-----------+-----------------------------+
| ``MF``    | More Fragments Flag         |
+-----------+-----------------------------+
| ``TTL``   | Time To Live                |
+-----------+-----------------------------+
| ``NFB``   | Number of Fragment Blocks   |
+-----------+-----------------------------+
| ``TL``    | Total Length                |
+-----------+-----------------------------+
| ``TDL``   | Total Data Length           |
+-----------+-----------------------------+
| ``BUFID`` | Buffer Identifier           |
+-----------+-----------------------------+
| ``RCVBT`` | Fragment Received Bit Table |
+-----------+-----------------------------+
| ``TLB``   | Timer Lower Bound           |
+-----------+-----------------------------+

.. code-block:: text

   DO {
      BUFID <- source|destination|protocol|identification;

      IF (FO = 0 AND MF = 0) {
         IF (buffer with BUFID is allocated) {
            flush all reassembly for this BUFID;
            Submit datagram to next step;
            DONE.
         }
      }

      IF (no buffer with BUFID is allocated) {
         allocate reassembly resources with BUFID;
         TIMER <- TLB;
         TDL <- 0;
         put data from fragment into data buffer with BUFID
            [from octet FO*8 to octet (TL-(IHL*4))+FO*8];
         set RCVBT bits [from FO to FO+((TL-(IHL*4)+7)/8)];
      }

      IF (MF = 0) {
         TDL <- TL-(IHL*4)+(FO*8)
      }

      IF (FO = 0) {
         put header in header buffer
      }

      IF (TDL # 0 AND all RCVBT bits [from 0 to (TDL+7)/8] are set) {
         TL <- TDL+(IHL*4)
         Submit datagram to next step;
         free all reassembly resources for this BUFID;
         DONE.
      }

      TIMER <- MAX(TIMER,TTL);

   } give up until (next fragment or timer expires);

   timer expires: {
      flush all reassembly with this BUFID;
      DONE.
   }
