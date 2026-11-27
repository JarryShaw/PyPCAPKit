.. _reassembly-integration:

Reassembly Integration
-----------------------

Where a new reassembly engine under :mod:`pcapkit.foundation.reassembly` plugs into
the package. Points 1 to 3 were ruled on the DTLS reassembly work in review of
:pr:`2451` (:issue:`2440`), whose issue does not hold them. Point 4 rests on
:pr:`2469`: reviewing how DTLS sizes a handshake message's buffer, the owner had DTLS
reassembly follow its RFCs. No issue holds that ruling.

The Rule
~~~~~~~~

#. **A protocol class does not handle or integrate reassembly itself.** The dissector
   stays a parser and does not reach into :mod:`pcapkit.foundation.reassembly`. A
   public method that parses a reassembled unit from its own octets is still a parser,
   so a protocol class may offer one (:issue:`2496`).
#. **A new engine needs a new** :mod:`pcapkit.toolkit` **helper** that declares which
   output engines (|dpkt|_, |pyshark|_, ``scapy``, the default) support it.
#. **A new engine's reassembled outcome needs a new**
   :mod:`pcapkit.foundation.analysis` **method** that parses it into a usable result,
   rather than leaving the caller raw reassembled bytes. The package mirrors
   :mod:`pcapkit.foundation.reassembly` with a module per engine, whose public names
   the package, :mod:`pcapkit.foundation` and :mod:`pcapkit.all` export
   (:issue:`2496`).
#. **Reassembly always follows the RFC's own definition**, never an algorithm this
   package invents. Where the RFC requires no algorithm -- buffer the whole message,
   accept overlaps -- the engine adds no timeout, cap or ordering rule of its own.

**TCP's gap cap is a safety limit, not a reassembly rule.** No RFC calls for
:data:`~pcapkit.utilities.config.TCP_GAP_LIMIT`, the widest gap TCP reassembly
zero-fills to merge a segment. It bounds zero-filled memory, as
:data:`~pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH` does for a field, and ``-1``
lifts it for the uncapped reassembly point 4 asks for. Ruled on :issue:`2546`.

**Every callback runs, and the first exception is re-raised**, for reassembly and
flow-tracing callbacks alike. One raising an :exc:`Exception` does not stop the
ones after it: the first such error propagates once the last has run, and a later
one is logged at debug level. Any other :exc:`BaseException`, such as
:exc:`KeyboardInterrupt`, stops them at once. Both run them through
:func:`~pcapkit.utilities.callbacks.run_callbacks`. Ruled in review of :pr:`2875`
(:issue:`2855`).

Package Layout
~~~~~~~~~~~~~~

**Each reassembly and flow tracing class has a package of its own, named after it**,
laid out as a protocol's is (:ref:`protocol-family-grouping`). Ruled on :issue:`2882`:

* Its ``reassembly`` or ``traceflow`` module holds the class, and ``data`` its data
  models where it has its own.
* Its ``__init__`` exports the class alone, and binds each class ``data`` defines as
  ``Data_<name>`` outside ``__all__``, as :mod:`pcapkit.foundation.reassembly.tcp` does.
* The IP base's package, :mod:`pcapkit.foundation.reassembly.ip`, holds the data models
  IPv4 and IPv6 share, so :mod:`pcapkit.foundation.reassembly.ipv4` and
  :mod:`pcapkit.foundation.reassembly.ipv6` have no ``data`` of their own.
* The bases stay in :mod:`pcapkit.foundation.reassembly.reassembly` and
  :mod:`pcapkit.foundation.traceflow.traceflow`, with their data models beside them in
  :mod:`pcapkit.foundation.reassembly.data` and :mod:`pcapkit.foundation.traceflow.data`.

:file:`tests/foundation/test_foundation_packages_2882_unit.py` fails on a package out of
this layout.

Parse Ownership
~~~~~~~~~~~~~~~

**The protocol class owns the parse of a reassembled outcome**, and
:mod:`pcapkit.foundation.analysis` is a public layer over it. Ruled on :issue:`2622`:

* The parse is a method of the protocol class:
  :meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>` for IPv4 and
  IPv6, :meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`
  for TCP,
  :meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`
  for a DTLS handshake message, and
  :meth:`SCTP.analyze <pcapkit.protocols.transport.sctp.protocol.SCTP.analyze>` for an
  SCTP user message.
* Each :mod:`pcapkit.foundation.analysis` function is a public wrapper that calls that
  method and holds no parsing of its own.
* The reassembly :class:`~pcapkit.foundation.reassembly.data.Deferred` calls the
  same method, on the reassembly's own ``__protocol_type__``. For IP, TCP and SCTP it
  passes the stops and context the extraction's engine parses its frames with: the
  default engine's, and none from a third-party engine, whose frames ignore them
  (:issue:`2933`). :func:`~pcapkit.foundation.analysis.ip.ip_datagram`,
  :func:`~pcapkit.foundation.analysis.tcp.tcp_datagram` and
  :func:`~pcapkit.foundation.analysis.sctp.sctp_message` take them as keyword-only
  ``layer``, ``protocol`` and ``context``, so given the same they return that
  ``packet`` (:issue:`2947`). The reassembler a TCP flow tracer builds for
  ``analyze`` takes them the same way (:issue:`2946`). For IP both also hand a
  protocol class's ``analyze`` the datagram's addresses and IP version, as a frame's IP
  layer hands its next layer, so its payload is dispatched as a frame's is
  (:issue:`2945`).
* Protocol code never imports :mod:`pcapkit.foundation` to do its own work; the
  dependency runs from ``foundation`` to the protocols. The protocol base's import from
  :mod:`pcapkit.foundation.registry.protocols` registers a class rather than parsing.
  :file:`tests/project/test_protocols_import_boundary_2622_unit.py` fails on any other
  import of :mod:`pcapkit.foundation` under :file:`pcapkit/protocols/` outside a
  ``TYPE_CHECKING`` block, the rest of :mod:`pcapkit.foundation.registry` included.

.. mermaid::

   flowchart TD
       ENG["pcapkit.foundation.engines<br/>an already-parsed frame"]
       TK["the pcapkit.toolkit.&lt;engine&gt; adapter the engine's<br/>\_\_reassembly\_\_ names, e.g. toolkit.pcap.dtls\_reassembly"]
       RE["each enabled reassembler the Extractor holds,<br/>by its registered name, advanced to the frame's timestamp"]
       DEF["Deferred: a datagram's packet,<br/>parsed on first read"]
       AN["pcapkit.foundation.analysis<br/>ip\_datagram, tcp\_datagram, dtls\_handshake, sctp\_message<br/>public wrappers, no parsing"]
       subgraph protocols ["pcapkit.protocols"]
           PM["the protocol class's parse method<br/>Protocol.analyze: IPv4, IPv6<br/>Transport.analyze: TCP<br/>DTLS.analyze\_handshake<br/>SCTP.analyze: SCTP"]
       end
       REG["pcapkit.foundation.registry.protocols"]

       ENG --> TK --> RE --> DEF
       DEF -->|"on the reassembly's \_\_protocol\_type\_\_"| PM
       AN --> PM
       protocols -.->|"registers a class, nothing else"| REG

No edge leaves :mod:`pcapkit.protocols` for the reassembly or the analysis layer;
:file:`tests/project/test_protocols_import_boundary_2622_unit.py` fails on one.

Compliance, Measured
~~~~~~~~~~~~~~~~~~~~~

**Point 1 holds for every engine.** None of
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`,
:class:`~pcapkit.protocols.transport.tcp.protocol.TCP`,
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS` and
:class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` imports or calls into
:mod:`pcapkit.foundation.reassembly`. Instead :mod:`pcapkit.foundation.engines` calls a
``pcapkit.toolkit.<engine>`` extraction function on an already-parsed frame and feeds
the result to the reassembly instance the
:class:`~pcapkit.foundation.extraction.Extractor` holds; for DTLS that function is
:func:`pcapkit.toolkit.pcap.dtls_reassembly` (:issue:`2496`). Every enabled
reassembler is reached by the name it is registered under in
:attr:`Extractor.__reassembly__ <pcapkit.foundation.extraction.Extractor.__reassembly__>`,
through :meth:`Extractor.make_reassembly
<pcapkit.foundation.extraction.Extractor.make_reassembly>` and the engine's adapter for
that name, and each is advanced to every frame's timestamp before the frame is fed
(:issue:`2814`).
:meth:`DTLS.read_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.read_handshake>`
and :meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`
are the parser methods the rule allows.

**Point 2 holds through the engines, not through one** :mod:`pcapkit.toolkit`
**helper.** Each engine's :attr:`EngineBase.__reassembly__
<pcapkit.foundation.engines.engine.EngineBase.__reassembly__>` maps every reassembler it
supports to the adapter that feeds it: a toolkit one it ships, or one registered with
:meth:`EngineBase.register_reassembly
<pcapkit.foundation.engines.engine.EngineBase.register_reassembly>`. So the maps together
declare which engines support a reassembler, and registering an adapter on an engine
makes it support one. An enabled reassembler with no entry is
disabled with an :class:`~pcapkit.utilities.warnings.AttributeWarning`, and an engine
with no entries at all, as :mod:`pcapkit.foundation.engines.pyshark`, disables
reassembly (:issue:`2814`). DTLS and SCTP have entries on the default engine alone.

**Flow tracing takes the same shape.** Every enabled flow tracer is made by the name it
is registered under in :attr:`Extractor.__traceflow__
<pcapkit.foundation.extraction.Extractor.__traceflow__>`, through
:meth:`Extractor.make_traceflow <pcapkit.foundation.extraction.Extractor.make_traceflow>`,
and finished at the end of the capture. Each engine's :attr:`EngineBase.__traceflow__
<pcapkit.foundation.engines.engine.EngineBase.__traceflow__>` maps every flow tracer it
supports to its toolkit adapter, written by :meth:`EngineBase.register_traceflow
<pcapkit.foundation.engines.engine.EngineBase.register_traceflow>`. An enabled tracer
with no entry is dropped with an :class:`~pcapkit.utilities.warnings.AttributeWarning`,
and an engine with no entries, as :mod:`pcapkit.foundation.engines.pypcap` and
:mod:`pcapkit.foundation.engines.pcap_ct`, disables flow tracing (:issue:`2843`).

**Every engine feeds what its maps hold.** Each one's ``read_frame`` calls
:meth:`EngineBase._reassemble <pcapkit.foundation.engines.engine.EngineBase._reassemble>`
and :meth:`EngineBase._traceflow <pcapkit.foundation.engines.engine.EngineBase._traceflow>`,
so an adapter registered on an engine that ships none, as PyShark, PyPCAP and pcap-ct
do for reassembly, is fed rather than refused: registering is how an engine gains
support (:issue:`2893`).
Each engine declares both maps itself, empty or not, and documents there how it calls
an adapter.
:file:`tests/foundation/engines/test_reassembly_feed_2893_unit.py` fails on an engine
whose ``read_frame`` leaves either uncalled, or that inherits either map rather than
declaring it.

**Point 3 holds for every engine.**
:func:`~pcapkit.foundation.analysis.ip.ip_datagram` parses a reassembled IPv4 or IPv6
datagram's payload by its payload protocol type, through
:meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>`;
:func:`~pcapkit.foundation.analysis.tcp.tcp_datagram` parses a reassembled TCP
datagram's by its ports, through
:meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`;
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes a reassembled
DTLS handshake message (:issue:`2496`), through
:meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`
(:issue:`2622`); and :func:`~pcapkit.foundation.analysis.sctp.sctp_message` parses a
reassembled SCTP user message's by its payload protocol identifier, through
:meth:`SCTP.analyze <pcapkit.protocols.transport.sctp.protocol.SCTP.analyze>`. IP and
TCP have analysis modules of their own, each function named for the datagram its engine
reassembles, by the owner's choice on :issue:`2581`; without them the rule held for DTLS
alone.

**Where the rule is silent, DTLS takes the IP/TCP shape** (:issue:`2531`), and so does
SCTP. IPv4, IPv6, TCP, DTLS and SCTP reassembly each set ``__protocol_type__`` and
report the parsed outcome as a datagram's ``packet``, deferred to first read by
:class:`~pcapkit.foundation.reassembly.data.Deferred`. Each ``Deferred`` runs the
parse behind its engine's analysis function, so a ``packet`` is what that function
returns, and binds it to ``__protocol_type__`` -- ``analyze`` for IP and TCP
(:issue:`2581`) and for SCTP, ``analyze_handshake`` for DTLS (:issue:`2622`) -- so a
subclass naming another protocol has its ``packet`` parsed by that one. They differ on
an incomplete outcome: IP, TCP and SCTP parse a contiguous payload, complete or not, as
``strict=False`` reports one, and hold :data:`None` only for the received runs
``strict=True`` reports; DTLS holds :data:`None` for any incomplete message.
