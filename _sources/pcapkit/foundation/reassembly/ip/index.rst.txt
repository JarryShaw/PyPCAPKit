======================
IP Datagram Reassembly
======================

The algorithm below follows the IP reassembly procedure of :rfc:`791`, using
``RCVBT`` (fragment received bit table). :rfc:`815` explains an alternative
that replaces ``RCVBT``; it is not used here.

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
| Acronym   | Description                 |
+===========+=============================+
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
         }
         Submit datagram to next step;
         DONE.
      }

      IF (no buffer with BUFID is allocated) {
         allocate reassembly resources with BUFID;
         TIMER <- TLB;
         TDL <- 0;
      }

      put data from fragment into data buffer with BUFID
         [from octet FO*8 to octet (TL-(IHL*4))+FO*8];
      set RCVBT bits [from FO to FO+((TL-(IHL*4)+7)/8)];

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

Because completion frees the buffer (:rfc:`791#section-3.2`), a fragment that
arrives after its datagram has completed opens a new buffer, which is later
reported as a separate incomplete datagram; this is intended (:issue:`1507`).

Departures from the procedure above:

* The timer is not set from ``TLB`` and ``TTL``. A buffer is abandoned a fixed
  timeout after its first-arriving fragment, on the capture's clock -- 60
  seconds by default, per :rfc:`1122#section-3.3.2` for IPv4 and
  :rfc:`8200#section-4.5` for IPv6.
* A buffer flushed by an unfragmented datagram reusing its ``BUFID`` is
  reported as an incomplete datagram rather than discarded.
* An IPv6 atomic fragment, one with fragment offset zero and **M** clear,
  flushes nothing: it is reassembled in isolation and the fragments buffered
  under its ``BUFID`` are kept, per :rfc:`6946#section-4` (:issue:`2270`).
* ``TDL`` starts at ``-1`` rather than ``0``, so that a datagram carrying no
  data can complete (:issue:`1359`).
* Only the final fragment's partial last ``RCVBT`` block is set. A non-final
  fragment carries a multiple of 8 octets, so one ending mid-block was cut or
  is malformed, and setting its last block would complete the datagram with
  octets nobody sent (:issue:`1567`).
* A datagram longer than the data buffer is never complete (:issue:`1566`).
* Nor is a datagram longer than its length field can declare: 65,535 octets
  with its header, all of which IPv4's Total Length counts and all but the
  fixed 40 octets of which IPv6's Payload Length counts. Linux rejects such a
  datagram too (:issue:`1585`). A fragment with Total Length 0, as TCP
  segmentation offload and BIG TCP leave one, declares no length
  (:issue:`1555`), so a datagram it carries past that bound grows the data
  buffer instead, and only the buffer bounds it.
