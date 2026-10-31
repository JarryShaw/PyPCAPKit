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
   output engines (``dpkt``, ``pyshark``, ``scapy``, the default) support it.
#. **A new engine's reassembled outcome needs a new**
   :mod:`pcapkit.foundation.analysis` **method** to parse that outcome into a usable
   result, rather than leaving the caller to interpret raw reassembled bytes.
#. **Reassembly always follows the RFC's own definition**, never an algorithm this
   package invents. Where the RFC states no required algorithm -- buffer the whole
   message, accept overlaps -- the engine does the same and adds no timeout, cap or
   ordering rule the RFC does not call for.

.. note::

   This page records the ruling as given. Whether the existing :class:`IP
   <pcapkit.foundation.reassembly.ip.IP>` and :class:`TCP
   <pcapkit.foundation.reassembly.tcp.TCP>` engines already follow points 2 and 3, and
   what the DTLS engine (:mod:`pcapkit.foundation.reassembly.dtls`) needs to catch up,
   is a separate compliance question, tracked apart from this page.
