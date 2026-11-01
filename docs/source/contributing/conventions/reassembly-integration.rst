.. _reassembly-integration:

Reassembly Integration
-----------------------

Where a new reassembly engine under :mod:`pcapkit.foundation.reassembly` plugs into
the rest of the package. The owner's ruling, given on the DTLS reassembly work of
:issue:`2440`.

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

Compliance, Measured
~~~~~~~~~~~~~~~~~~~~~

**Point 1 holds for every engine.** None of
:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`,
:class:`~pcapkit.protocols.transport.tcp.TCP` and
:class:`~pcapkit.protocols.application.dtls.DTLS` imports or calls into
:mod:`pcapkit.foundation.reassembly` at all. The real path is
:mod:`pcapkit.foundation.engines` calling a ``pcapkit.toolkit.<engine>`` extraction
function on an already-parsed frame, feeding the result to the reassembly instance the
:class:`~pcapkit.foundation.extraction.Extractor` holds; for DTLS that function is
:func:`pcapkit.toolkit.pcap.dtls_reassembly` (:issue:`2496`).
:meth:`DTLS.read_handshake <pcapkit.protocols.application.dtls.DTLS.read_handshake>`
is the parser method the rule allows.

**No engine meets point 2.** No single :mod:`pcapkit.toolkit` helper enumerates which
output engines support a given reassembly engine. Support is established ad hoc, per
engine backend, by defining the extraction functions, by defining them raising
:exc:`~pcapkit.utilities.exceptions.UnsupportedCall`, or by disabling reassembly at the
engine level, as :mod:`pcapkit.foundation.engines.pyshark` does. DTLS defines them for
the default engine and is disabled at the engine level on every other.

**Point 3 holds for DTLS alone.**
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` parses a reassembled DTLS
handshake message (:issue:`2496`). IP and TCP have no such method: what parses their
outcome is the general-purpose
:meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>` dispatcher,
reused via :class:`~pcapkit.foundation.reassembly.data.data.Deferred`, not a method
written for reassembly specifically.

DTLS differs from the IP/TCP shape where the rule is silent: its reassembled body is
reported eagerly, with no deferred ``packet``, and
:class:`~pcapkit.foundation.reassembly.dtls.DTLS` sets no ``__protocol_type__``
(:issue:`2531`).
