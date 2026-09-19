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
            timestamp = float(
                frame.info.time_epoch),     # capture timestamp
          )

   reasm.ipv4.datagram
       Data structure for **reassembled IPv4 datagram** (element from
       :attr:`IPv4.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) datagram
           |--> (Info) data
           |     |--> 'completed' : (Completion) COMPLETE --> reassembled in whole
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
           |     |--> 'conflict' : (tuple) octet ranges on which two fragments disagreed
           |     |                  |--> (tuple) (first, last), absolute and inclusive
           |     |                  |--> ...
           |--> (Info) data
           |     |--> 'completed' : (Completion) PARTIAL or TIMEOUT --> incomplete
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
           |     |--> 'conflict' : (tuple) octet ranges on which two fragments disagreed
           |     |                  |--> (tuple) (first, last), absolute and inclusive
           |     |                  |--> ...
           |--> (Info) data ...

       .. note::

          ``packet`` is analysed on the first read, not when the datagram is
          submitted. A datagram is submitted for *every* frame -- an unfragmented
          one included, since nothing upstream filters it out -- and the analysis
          is a second full parse of the payload, so running it eagerly charged
          every caller for a result most never read. Reading the attribute, or any
          mapping view of it (``datagram['packet']``, ``to_dict()``, ``items()``,
          ``repr()``), runs it and keeps the result; see
          :class:`~pcapkit.foundation.reassembly.data.data.Deferred`.

       .. note::

          ``completed`` and ``conflict`` are independent signals: a datagram
          can be :attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`
          and still carry a non-empty ``conflict``. :rfc:`791` resolves an
          overlapping fragment's disagreement itself -- "this procedure will
          use the more recently arrived copy in the data buffer" -- the
          opposite resolution from TCP's first-write-wins
          (:rfc:`9293#section-3.10`, fixed for TCP by #443) -- so a contested
          range never leaves a hole on its own, and ``conflict`` is what lets
          a caller tell a clean datagram from a contested one. See #477.

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
           |                         |--> 'timestamp' : (float) capture timestamp of the
           |                         |                          first-arriving fragment
           |                         |--> 'conflict' : (list) octet ranges on which an arriving
           |                         |                  fragment disagreed with bytes already in
           |                         |                  'datagram'
           |                         |                  |--> (tuple) (first, last), absolute and
           |                         |                               inclusive
           |                         |                  |--> ...
           |--> (tuple) BUFID ...

       .. note::

          ``conflict`` is only ever appended to, and is checked against
          ``datagram`` and ``RCVBT`` *before* an arriving fragment's own write
          and bookkeeping touch them -- see
          :meth:`IP._detect_conflicts <pcapkit.foundation.reassembly.ip.IP._detect_conflicts>`.
          ``RCVBT`` records receipt in 8-octet blocks, which is coarser than
          the octet a conflict needs; ``TDL`` is what recovers the exact
          extent for the one block that can be partially real -- the final
          fragment's own tail -- so a conflict here is never wider than the
          octets that genuinely disagreed, even inside that block.

       .. note::

          A buffer is abandoned once the reassembly timeout elapses on the
          *capture's* clock -- 60 seconds by default, per
          :rfc:`1122#section-3.3.2` for IPv4 and :rfc:`8200#section-4.5` for
          IPv6, counted from the first-arriving fragment. Its datagram is
          reported with ``completed`` set to
          :attr:`Completion.TIMEOUT <pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT>`
          rather than
          :attr:`~pcapkit.foundation.reassembly.data.data.Completion.PARTIAL`,
          which is what tells "these fragments are gone" apart from "these
          fragments had not arrived yet". See
          :meth:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase.expire`.
