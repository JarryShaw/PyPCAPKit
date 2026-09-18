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
       is as following, with ``ipv6_info`` the IPv6
       :attr:`~pcapkit.protocols.protocol.ProtocolBase.info` and
       ``ipv6_frag_info`` the Fragment header's:

       .. code-block:: python

          hdr_len = ipv6_info.hdr_len - ipv6_frag.length
          payload = bytearray(ipv6_info.fragment.payload)

          packet_dict = dict(
            bufid = (
                ipv6_info.src,              # source IP address
                ipv6_info.dst,              # destination IP address
                ipv6_frag_info.id,          # identification
                ipv6_frag_info.next,        # next header field in IPv6 Fragment Header
            ),
            num = frame.info.number,        # original packet range number
            fo = ipv6_frag_info.offset,     # fragment offset, in octets
            ihl = hdr_len,                  # header length, only headers before IPv6-Frag
            mf = ipv6_frag_info.mf,         # more fragment flag
            tl = hdr_len + len(payload),    # total length, header includes
            header = ipv6_info.fragment
                     .header[:hdr_len],     # raw bytes type header before IPv6-Frag
            payload = payload,              # raw bytearray type payload after IPv6-Frag
            timestamp = float(
                frame.info.time_epoch),     # capture timestamp
          )

       .. note::

          ``ihl``, ``header`` and ``tl`` all stop short of the 8-octet Fragment
          header, because :rfc:`8200#section-4.5` says it is not present in the
          reassembled packet. :attr:`IPv6.hdr_len <pcapkit.protocols.data.internet.ipv6.IPv6.hdr_len>`
          does count it -- it is a header length, and the Fragment header is one
          of the extension headers it has walked -- so the adapters subtract it
          back off. All four adapters (``pcap``, ``pcapng``, ``dpkt`` and
          ``scapy``) agree on the three fields; they used to report three
          different values for ``tl`` alone, which is what #415 was about.

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
           |     |--> 'completed' : (Completion) COMPLETE --> reassembled in whole
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
           |     |--> 'conflict' : (tuple) octet ranges on which two fragments disagreed
           |     |                  |--> (tuple) (first, last), absolute and inclusive
           |     |                  |--> ...
           |--> (Info) data
           |     |--> 'completed' : (Completion) PARTIAL or TIMEOUT --> incomplete
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
           |     |--> 'conflict' : (tuple) octet ranges on which two fragments disagreed
           |     |                  |--> (tuple) (first, last), absolute and inclusive
           |     |                  |--> ...
           |--> (Info) data ...

       .. note::

          ``header`` is the fragment's unfragmentable part with one field
          rewritten: the Next Header field of its last header carries the
          Fragment header's Next Header value, as :rfc:`8200#section-4.5`
          requires of a reassembled packet. Without that rewrite the datagram
          would still advertise a Fragment header (``44``) on a datagram that is
          no longer a fragment. The Payload Length field is *not* adjusted, so it
          still describes the first fragment rather than the reassembled
          datagram; use ``len(payload)`` instead.

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
