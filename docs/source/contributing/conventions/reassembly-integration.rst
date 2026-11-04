.. _reassembly-integration:

Reassembly Integration
-----------------------

Where a new reassembly engine under :mod:`pcapkit.foundation.reassembly` plugs into
the rest of the package. Points 1 to 3 are the owner's ruling on the DTLS reassembly
work, applied in review of :pr:`2451` (:issue:`2440`); the issue itself does not hold
it. Point 4 rests on :pr:`2469`, which settled the DTLS case alone: in review of
how DTLS sizes a handshake message's buffer, the owner had DTLS reassembly follow its
RFCs.
No issue holds that ruling.

The Rule
~~~~~~~~

#. **A protocol class does not handle or integrate reassembly itself.** The protocol
   dissector stays a parser; it does not reach into
   :mod:`pcapkit.foundation.reassembly` directly. A public method that parses a
   reassembled unit from its own octets is still a parser, so a protocol class may
   offer one (:issue:`2496`).
#. **A new engine needs a new** :mod:`pcapkit.toolkit` **helper** that declares which
   output engines (|dpkt|_, |pyshark|_, ``scapy``, the default) support it.
#. **A new engine's reassembled outcome needs a new**
   :mod:`pcapkit.foundation.analysis` **method** to parse that outcome into a usable
   result, rather than leaving the caller to interpret raw reassembled bytes. The
   package mirrors :mod:`pcapkit.foundation.reassembly`: a module per engine, whose
   public names the package, :mod:`pcapkit.foundation` and :mod:`pcapkit.all`
   export (:issue:`2496`).
#. **Reassembly always follows the RFC's own definition**, never an algorithm this
   package invents. Where the RFC states no required algorithm -- buffer the whole
   message, accept overlaps -- the engine does the same and adds no timeout, cap or
   ordering rule the RFC does not call for.

**TCP's gap cap is a safety limit, not a reassembly rule.** No RFC calls for
:data:`~pcapkit.utilities.config.TCP_GAP_LIMIT`, the widest gap TCP reassembly
zero-fills to merge a segment. It bounds the memory a capture can have zero-filled, as
:data:`~pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH` does for a field, and ``-1``
lifts it to give the uncapped reassembly point 4 asks for. Ruled on :issue:`2546`.

Parse Ownership
~~~~~~~~~~~~~~~

**The protocol class owns the parse of a reassembled outcome**, and
:mod:`pcapkit.foundation.analysis` is a public layer over it. Ruled on :issue:`2622`:

* The parse is a method of the protocol class:
  :meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>` for IPv4 and
  IPv6, :meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`
  for TCP, and
  :meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`
  for a DTLS handshake message.
* Each :mod:`pcapkit.foundation.analysis` function is a public wrapper that calls that
  method and holds no parsing of its own.
* The reassembly :class:`~pcapkit.foundation.reassembly.data.data.Deferred` calls the
  same method, on the reassembly's own ``__protocol_type__``.
* Protocol code never imports :mod:`pcapkit.foundation` to do its own work: the
  dependency runs from ``foundation`` to the protocols. What the protocol base does
  import from :mod:`pcapkit.foundation.registry.protocols` registers a class rather
  than parsing. :file:`tests/project/test_protocols_import_boundary_2622_unit.py` fails
  on any other import of :mod:`pcapkit.foundation` under :file:`pcapkit/protocols/`
  made outside a ``TYPE_CHECKING`` block, the rest of
  :mod:`pcapkit.foundation.registry` included.

Compliance, Measured
~~~~~~~~~~~~~~~~~~~~~

**Point 1 holds for every engine.** None of
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`,
:class:`~pcapkit.protocols.transport.tcp.protocol.TCP` and
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS` imports or calls into
:mod:`pcapkit.foundation.reassembly` at all. The real path is
:mod:`pcapkit.foundation.engines` calling a ``pcapkit.toolkit.<engine>`` extraction
function on an already-parsed frame, feeding the result to the reassembly instance the
:class:`~pcapkit.foundation.extraction.Extractor` holds; for DTLS that function is
:func:`pcapkit.toolkit.pcap.dtls_reassembly` (:issue:`2496`).
:meth:`DTLS.read_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.read_handshake>`
and :meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`
are the parser methods the rule allows.

**No engine meets point 2.** No single :mod:`pcapkit.toolkit` helper enumerates which
output engines support a given reassembly engine. Support is established ad hoc, per
engine backend, by defining the extraction functions, by defining them raising
:exc:`~pcapkit.utilities.exceptions.UnsupportedCall`, or by disabling reassembly at the
engine level, as :mod:`pcapkit.foundation.engines.pyshark` does. DTLS defines them for
the default engine and is disabled at the engine level on every other.

**Point 3 holds for every engine.**
:func:`~pcapkit.foundation.analysis.ip.ip_datagram` parses a reassembled IPv4 or IPv6
datagram's payload by its payload protocol type, through
:meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>`;
:func:`~pcapkit.foundation.analysis.tcp.tcp_datagram` parses a reassembled TCP
datagram's by its ports, through
:meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`;
and :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes a reassembled
DTLS handshake message (:issue:`2496`), through
:meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`
(:issue:`2622`). The owner chose on :issue:`2581` to give IP and TCP modules of their
own, each function named for the datagram its engine reassembles, rather than leave
their outcomes to those dispatchers with no analysis method, which kept the rule true
for DTLS alone.

**Where the rule is silent, DTLS takes the IP/TCP shape** (:issue:`2531`). IPv4, IPv6,
TCP and DTLS reassembly each set ``__protocol_type__``, and each reports its parsed
outcome as a datagram's ``packet``, deferred to first read by
:class:`~pcapkit.foundation.reassembly.data.data.Deferred`. Each ``Deferred`` runs the
parse behind its engine's analysis function, so a ``packet`` is what that function
returns. Each binds that parse to ``__protocol_type__``, calling its ``analyze`` for
IP and TCP (:issue:`2581`) and its ``analyze_handshake`` for DTLS (:issue:`2622`), so a
subclass naming another protocol has its ``packet`` parsed by that one. The engines
differ in what an incomplete outcome holds. IP and TCP parse a contiguous payload
whether or not it is complete, as ``strict=False`` reports one, and hold :data:`None`
only for the received runs ``strict=True`` reports; DTLS holds :data:`None` for any
incomplete message.
