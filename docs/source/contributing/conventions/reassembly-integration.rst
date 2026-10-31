.. _reassembly-integration:

Reassembly Integration
-----------------------

Where a new reassembly engine under :mod:`pcapkit.foundation.reassembly` plugs into
the rest of the package. The owner's ruling, on this session's DTLS reassembly work.

The Rule
~~~~~~~~

#. **A protocol class does not handle or integrate reassembly itself.** The protocol
   dissector stays a parser; it does not reach into
   :mod:`pcapkit.foundation.reassembly` directly.
#. **A new engine needs a new** :mod:`pcapkit.toolkit` **helper** that declares which
   output engines (|dpkt|_, |pyshark|_, ``scapy``, the default) support it.
#. **A new engine's reassembled outcome needs a new**
   :mod:`pcapkit.foundation.analysis` **method** to parse that outcome into a usable
   result, rather than leaving the caller to interpret raw reassembled bytes.
#. **Reassembly always follows the RFC's own definition**, never an algorithm this
   package invents. Where the RFC states no required algorithm -- buffer the whole
   message, accept overlaps -- the engine does the same and adds no timeout, cap or
   ordering rule the RFC does not call for.

Compliance, Measured
~~~~~~~~~~~~~~~~~~~~~

**Point 1 is an existing, enforced precedent.** Neither
:class:`~pcapkit.protocols.internet.ipv4.IPv4` nor
:class:`~pcapkit.protocols.internet.ipv6.IPv6` nor
:class:`~pcapkit.protocols.transport.tcp.TCP` imports or calls into
:mod:`pcapkit.foundation.reassembly` at all. The real path is
:mod:`pcapkit.foundation.engines` calling a ``pcapkit.toolkit.<engine>`` extraction
function on an already-parsed frame, feeding the result to the reassembly instance the
:class:`~pcapkit.foundation.extraction.Extractor` holds.

**Points 2 and 3 describe infrastructure that does not exist yet, for any engine.**
No single :mod:`pcapkit.toolkit` helper enumerates which output engines support a given
reassembly engine -- support is established ad hoc, per engine backend, in three
different shapes (define the extraction functions; define them raising
:exc:`~pcapkit.utilities.exceptions.UnsupportedCall`; or disable reassembly at the
engine level, as :mod:`pcapkit.foundation.engines.pyshark` does). No
:mod:`pcapkit.foundation.analysis` module exists; what parses a reassembled outcome
today is the pre-existing, general-purpose
:meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>` dispatcher,
reused via :class:`~pcapkit.foundation.reassembly.data.data.Deferred`, not a method
written for reassembly specifically. So points 2 and 3 are a forward-looking ask, not
yet a pattern any engine follows.

**The DTLS reassembly work on** :pr:`2451` **violates point 1.**
:class:`~pcapkit.protocols.application.dtls.DTLS` imports
:class:`~pcapkit.foundation.reassembly.dtls.DTLS` directly and calls it from
:meth:`DTLS.read`, which no other protocol class does. Its own module docstring notes
the further divergence from the IP/TCP shape: it is "not toolkit-fed", reports its
reassembled body eagerly instead of through a :class:`Deferred
<pcapkit.foundation.reassembly.data.data.Deferred>`, and sets no
``__protocol_type__``.
