Help Wanted
===========

.. important::

   This page mirrors the `discussion thread
   <https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ started on GitHub.
   The thread holds the proposals as they were first raised, together with a
   comment recording which of them have since landed; this page is the
   maintained copy, kept in step with the code. So where a proposal has been
   implemented it is described as implemented here, and only the work that is
   genuinely still open is asked for. Please leave notes in the thread rather
   than against this page.

As PyPCAPKit reached its *16k* lines of code and *800th* commit, it seemed
better to record the project's enhancement proposals somewhere durable than to
leave them scattered. They were raised in the discussion thread, and this page
is where they are kept up to date.

Pull requests for anything still open, and new ideas of your own, are very
welcome. For questions, leave a note in the `discussion thread
<https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ or under the `Q&A
category <https://github.com/JarryShaw/PyPCAPKit/discussions/categories/q-a>`__.

.. note::

   This page tracks **feature requests** -- what is not implemented yet, and
   what a contributor could pick up. It is not an issue tracker. Where work on
   something listed here turns up a **defect** in code that already exists, the
   defect belongs in `the issue tracker
   <https://github.com/JarryShaw/PyPCAPKit/issues>`__ and is linked from here,
   not written up as prose on this page. A design question that needs a decision
   before anyone can implement it -- as against something simply being broken --
   is a request and does belong here.

Wish you enjoy **PyPCAPKit**!!!

More Protocols, More!!!
-----------------------

Plenty of protocols are not decoded yet, and every one of them is wanted.
Adding one is about the most self-contained contribution there is: a schema
class, a data class and a protocol class, as sketched in
`discussion #251 <https://github.com/JarryShaw/PyPCAPKit/discussions/251>`__.
The reply in that thread is the closest thing the project has to a
step-by-step guide for adding a protocol, and is worth reading before starting
one. Grouped by each TCP/IP layer and ordered by protocol name alphabetically,
the ones outstanding are,

* Link Layer: DSL, EAPOL, FDDI, ISDN, LINUX_SLL, LINUX_SLL2, NDP, PPP
* Internet Layer: ECN, ICMP, ICMPv6, IGMP, Shim6
* Transport Layer: DCCP, RSVP
* Application Layer: BGP, DHCP, DHCPv6, DNS, DTLS, IMAP, LDAP, MQTT, NNTP,
  NTP, ONC/RPC, POP, QUIC, RIP, RTP, SIP, SMTP, SNMP, SSH, Telnet, TLS/SSL,
  XMPP

Several of these come in pairs that want a shared abstract base rather than two
independent implementations, in the way
:class:`~pcapkit.protocols.internet.ip.IP` already covers its family: ICMP with
ICMPv6, TLS/SSL with DTLS, and ``LINUX_SLL`` with ``LINUX_SLL2``.
:class:`~pcapkit.protocols.link.vlan.VLAN` is the closer precedent for a pair
whose *layout* is identical -- it holds the whole of the tag, and
:class:`~pcapkit.protocols.link.c_tag.C_Tag` and
:class:`~pcapkit.protocols.link.s_tag.S_Tag` add only how each names itself.

.. note::

   Some of these have an empty, protocol-named file under a
   ``NotImplemented`` folder. **Those files are not a roadmap.** They were
   scratch reminders the author left himself before this page existed, so a
   stub's presence does not mean a protocol is planned or claimed, and its
   absence does not mean the protocol is unwanted: ``LINUX_SLL``, ``QUIC`` and
   **DTLS** have no stub and are on the list above, while **NGAP** had none
   either and is implemented. Take this page as the record and ignore the
   folder.

   **ESP**, **SCTP** and **NGAP** are no longer listed because they are
   implemented.

SCTP
~~~~

**Done.** :class:`~pcapkit.protocols.transport.sctp.SCTP` is a first-class
transport layer protocol implemented per :rfc:`9260`: the common header, all
thirteen chunk types the RFC defines, its eight chunk parameters, its thirteen
error causes, and CRC32c checksum verification.

One note on how it differs from its siblings. The next layer is dispatched
on the DATA chunk's *payload protocol identifier* through
:func:`~pcapkit.foundation.registry.protocols.register_sctp`, not on port
numbers, so :func:`~pcapkit.foundation.registry.protocols.register_apptype`
deliberately does not fan out to it.

What is still wanted is the registered-but-unimplemented type codes. IANA
registers considerably more than :rfc:`9260` defines, and the surplus falls
through to the generic handlers rather than failing the extraction -- so a
capture using one parses, but yields an opaque chunk instead of its fields.
As things stand that is 17 of the 30 registered chunk types, 24 of the 32
chunk parameters and 10 of the 23 error causes; :doc:`pcapkit/const/sctp`
lists them all.

The other thing wanted for SCTP is reassembly, which no protocol beyond IP and
TCP has -- see `Reassembly Beyond IP and TCP`_ below, since it needs work in
:mod:`pcapkit.foundation` rather than in the protocol.

ESP
~~~

**Done.** :class:`~pcapkit.protocols.internet.esp.ESP` -- abandoned in the
``NotImplemented`` folder for years, because of design flaws within PyPCAPKit
at the time -- now parses without keys, and decrypts when a Security
Association is supplied through the protocol keyed
:mod:`pcapkit.corekit.context` channel.

What is still wanted there is wider algorithm coverage. The two enumerations
under :doc:`pcapkit/const/esp` carry every transform IANA has registered -- 36
:class:`~pcapkit.const.esp.cipher.Cipher` members and 15
:class:`~pcapkit.const.esp.integrity.Integrity` members -- but
:data:`~pcapkit.protocols.internet.esp.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.INTEGRITY_SUITES` apply only five of
each, and two of those ten are the no-ops ``ENCR_NULL`` and ``NONE``. So the
real coverage is AES-CBC and AES-GCM at all three tag lengths for encryption,
and HMAC-SHA1-96 plus the three :rfc:`4868` HMAC-SHA2 truncations for
integrity.

Not implemented, roughly in the order a capture is likely to want them:
AES-CTR [:rfc:`3686`], AES-CCM at all three tag lengths [:rfc:`4309`],
ChaCha20-Poly1305 [:rfc:`7634`], AES-XCBC-MAC-96 [:rfc:`3566`], AES-CMAC-96
[:rfc:`4494`], the AES-GMAC family and its ``ENCR_NULL_AUTH_AES_GMAC``
counterpart [:rfc:`4543`], and then the Camellia, implicit-IV [:rfc:`8750`] and
MGM [:rfc:`9227`] families. Extended Sequence Numbers are not implemented
either, and are the one item on this list that is not simply a table entry: the
high-order 32 bits are never transmitted, so recovering them is stateful, and
they widen both the ICV coverage and the AEAD associated data.

Two structural notes for anyone starting. Adding an integrity algorithm that is
not an HMAC needs more than a row --
:class:`~pcapkit.protocols.internet.esp.IntegritySuite` records the digest as
the name of a :mod:`hashlib` constructor, which AES-XCBC and AES-CMAC are not.
And :func:`~pcapkit.protocols.internet.esp.load_cryptography` imports only the
``ciphers`` submodules of :mod:`cryptography`, so the AEAD and CMAC primitives
have to be added there before a cipher suite can reach them. Unsupported
algorithms are refused loudly, when the Security Association is constructed
rather than when a packet is read, so nothing decodes wrongly in the meantime.

Mobility Header
~~~~~~~~~~~~~~~

**Done.**
:class:`~pcapkit.protocols.internet.mh.MH` now decodes and constructs the whole
registry: **all 24 registered message data types**, **all 4 CGA extensions**, and
**all 71 registered options**. Every one of them is registered in
:attr:`~pcapkit.protocols.internet.mh.MH.__message__`,
:attr:`~pcapkit.protocols.internet.mh.MH.__option__` or
:attr:`~pcapkit.protocols.internet.mh.MH.__extension__` with both a ``_read_``
and a ``_make_`` handler.

Every message type and every one of those options round-trips byte-for-byte
through the public API -- ``make`` then ``read`` then ``make`` again reproduces
the same octets, which
:file:`tests/protocols/test_option_roundtrip_unit.py` checks for the whole
registry. The **four CGA extensions round-trip end to end as well**, which they
could not do for as long as the CGA Parameters option -- the only thing that can
carry a CGA extension on the wire -- was unparsable. Both of the shared
field-machinery faults behind that have since been fixed, so no ``mh-extension``
entry remains in that test's ``EXPECTED_FAILURES``.

The sub-registries turned out to be the easy half, as predicted: binding
revocation types and triggers, handoff indicators, access network identifier
sub-options, flow identification and flow binding sub-options, LMA-controlled MAG
parameters, DNS update status, traffic selector formats and QoS attributes were
already generated in full under :doc:`pcapkit/const/mh`, and **no new
enumeration or vendor crawler was needed**. Two value sets did have to be added
to ``mh.py`` itself rather than to :mod:`pcapkit.const.mh`, because IANA
registers neither: the localized routing acknowledgment status codes of
:rfc:`6705#section-10.2`
(:class:`~pcapkit.protocols.internet.mh.LocalizedRoutingStatus`) and the local
mobility anchor address option codes of :rfc:`5949#section-6.2.2`
(:class:`~pcapkit.protocols.internet.mh.LMAAddressCode`), alongside the two
:rfc:`5568` sets that were already there.

The CGA Parameters option (type 12) was the last one left on the generic handler,
and it is now registered like the rest. It was unreachable rather than
unimplemented: two faults in shared field machinery stood in the way, both
outside the mobility header --
`#445 <https://github.com/JarryShaw/PyPCAPKit/issues/445>`__, a nested schema
could not reach the enclosing packet's fields by name, and
`#446 <https://github.com/JarryShaw/PyPCAPKit/issues/446>`__, a
:class:`~pcapkit.corekit.fields.misc.ForwardMatchField`'s non-consuming bytes
counted towards the schema's length. Both had to be fixed for this option to
parse, which is why the half-fix was reverted rather than shipped; they landed
separately, and ``test_mh_cga_parameters_option_now_parses`` is the pinning test
renamed to record it. Fixing the option reached the whole
:attr:`~pcapkit.protocols.internet.mh.MH.__extension__` registry with it, since
it is the only carrier a CGA extension has -- four ``EXPECTED_FAILURES`` entries
went green at once.

What is left, and why:

* **Payloads that belong to another protocol** are carried opaquely for now. The
  multicast options (54, 56, 57, 60 and 61) embed :rfc:`3810` MLD or :rfc:`3376`
  IGMP address records, and the traffic selectors of :rfc:`6089` and :rfc:`7222`
  embed the flag-driven range lists of :rfc:`6088`. Each is a separate registry
  with its own dissector's worth of structure; the mobility options around them
  are fully decoded, and each records which format its payload is in.

  What is wanted is to carry these as :class:`~pcapkit.protocols.misc.raw.Raw`
  rather than as bare :obj:`bytes`, dispatched through a **per-payload registry**
  in the style of :attr:`MH.__option__ <pcapkit.protocols.internet.mh.MH.__option__>`,
  keyed on the field that already names the format --
  :attr:`~pcapkit.protocols.schema.internet.mh.TrafficSelectorSuboption.ts_format`
  for the traffic selectors, and the mode flag for MLD against IGMP on the
  multicast options. ``Raw`` is already what an unregistered dispatch falls back
  to everywhere else in the package, so this makes the mobility header consistent
  with the rest rather than inventing a convention; and once a dissector for one
  of these formats exists, registering it needs no change at the option site.

  It wants a registry of its own rather than
  :meth:`~pcapkit.protocols.protocol.Protocol._decode_next_layer`, which is
  only ever called at a layer boundary and appends to the frame's protocol chain.
  An MLD address record inside a mobility option did not follow MH on the wire,
  so putting it in that chain would make ``layer=`` and ``protocol=`` limits
  behave wrongly. Changing the parsed shape from :obj:`bytes` to ``Raw`` also
  changes what existing captures dump to, so it is its own change.

Two wire-format traps are worth knowing before touching this code, since both
look like ordinary fields and are not:

* :rfc:`7411`'s two multicast options measure their length field in **32-bit
  words**, and exclude the option-code and status octets as well as the type and
  length ones -- so the option occupies ``4 + length * 4`` octets, not
  ``length + 2``.
* :rfc:`5213#section-8.8`'s timestamp is **not** an :rfc:`1305` NTP timestamp,
  though the mobility header carries both. It counts from the UNIX epoch in a
  48/16 fixed-point split, where NTP counts from 1900 in a 32/32 one, so reading
  one as the other is wrong in the epoch and in both field widths. They have
  separate types for that reason:
  :class:`~pcapkit.protocols.internet.mh.PMIPv6Timestamp` and
  :class:`~pcapkit.protocols.internet.mh.NTPTimestamp`.

DTLS
~~~~

**Not started**, and unlike everything in the list above it has no stub in the
tree at all -- only TLS/SSL does. It earns its own entry because the registries
have moved ahead of it, and a growing part of SCTP's surface now names a protocol
that does not exist:

* the DTLS chunk, type 65 of :class:`~pcapkit.const.sctp.chunk.Chunk`, and the
  DTLS Key Management chunk parameter, ``0x8006`` of
  :class:`~pcapkit.const.sctp.parameter.Parameter` -- both fall through to the
  generic handlers, so they parse as opaque;
* four of its error causes, 100 to 103 of
  :class:`~pcapkit.const.sctp.cause_code.CauseCode`;
* seven payload protocol identifiers -- 47 (Diameter over DTLS/SCTP), 66 to 69
  (NGAP, XnAP, F1AP and E1AP, each over DTLS over SCTP) and 4242 (DTLS chunk
  key management).

That last group is the one that bites. NGAP over DTLS over SCTP is PPID 66, and
even with an NGAP dissector registered against it the bytes arriving are a DTLS
record rather than an NGAP PDU, so they can only degrade to
:class:`~pcapkit.protocols.misc.raw.Raw`. DTLS therefore blocks NGAP over DTLS,
asked for in `discussion #251
<https://github.com/JarryShaw/PyPCAPKit/discussions/251>`__, independently of
whether NGAP itself is implemented.

A record-layer dissector is enough to unblock that -- content type, version,
epoch, sequence number, length, and the fragment offset and length DTLS adds to
handshake messages. Decryption is a separate question and is not needed to make
the record structure legible, in the same way :class:`ESP
<pcapkit.protocols.internet.esp.ESP>` parses without keys. DTLS over UDP is the
other half of the same work and wants the same dissector.

Registered, But Not Dissected
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A different shape of gap from the empty stubs, and easy to miss because nothing
announces it. The :doc:`pcapkit/const/reg` enumerations are complete, but only a
small part of each is bound to a dissector; everything else resolves to
:class:`~pcapkit.protocols.misc.raw.Raw`, so the capture parses without
complaint and yields nothing useful.

* **3 of the 219** :class:`~pcapkit.const.reg.linktype.LinkType` values --
  ``ETHERNET``, ``IPV4`` and ``IPV6``, declared identically in
  :class:`~pcapkit.protocols.misc.pcap.frame.Frame` and
  :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`.
* **16 of the 151** :class:`~pcapkit.const.reg.transtype.TransType` values, in
  :attr:`Internet.__proto__
  <pcapkit.protocols.internet.internet.Internet.__proto__>`.
* **7 of the 160** :class:`~pcapkit.const.reg.ethertype.EtherType` values, in
  :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`: ARP,
  RARP, IPv4, IPv6, IPX and both VLAN tags.
* **7 bindings over 5 port numbers, out of 8182**
  :class:`~pcapkit.const.reg.apptype.AppType` members -- TCP 20 to FTP-DATA and
  21 to FTP, port 80 and 8080 to HTTP on both TCP and UDP, and UDP 1701 to L2TP.
  The two counts differ because 80 and 8080 are each bound twice, once per
  transport.
* **2 of the 75**
  :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
  values, in :attr:`SCTP.__proto__
  <pcapkit.protocols.transport.sctp.SCTP.__proto__>`: PPIDs 60 and 66, both to
  :class:`~pcapkit.protocols.application.ngap.NGAP`. Every other DATA chunk
  payload is ``Raw`` until something calls
  :func:`~pcapkit.foundation.registry.protocols.register_sctp`.

Most of those want a dissector written and are covered by the stub list above.
A handful wanted only a table entry, because the dissector was already there,
and those have now been made:

* **Done.** :class:`~pcapkit.protocols.link.ospf.OSPF` is bound at
  ``TransType`` 89 (``OSPFIGP``) and
  :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` at UDP port 1701. Binding them
  turned up three defects that had kept OSPF from parsing anything at all --
  ``read`` consulted the schema *class* rather than the parsed header,
  :attr:`~pcapkit.protocols.link.ospf.OSPF.alias` read an ``_info`` that does
  not exist until ``read`` has returned, and both classes dispatched the
  remaining payload *length* as if it were a protocol code. ``__index__`` still
  raises on both, which is correct: neither is reached through a link-layer
  EtherType.
* **Done.** :class:`~pcapkit.protocols.application.ftp.FTP_DATA` is bound at TCP
  port 20 (IANA ``ftp-data``). It is a thin
  :class:`~pcapkit.protocols.misc.raw.Raw` subclass, so this buys the payload a
  *name* rather than a parse -- which is the right answer for a data channel
  carrying an arbitrary file.
* **Done.** HTTP is additionally bound on 8080 (IANA ``http-alt``, "HTTP
  Alternate (see port 80)") on both TCP and UDP. **8443 is deliberately left
  unbound**: IANA registers it as ``pcsync-https``, not as an HTTP alternate,
  and de-facto 8443 traffic is TLS-wrapped, which pcapkit cannot parse -- see
  the ``tls`` stub above. Binding it would feed a TLS record to an HTTP parser.
* **Done.** The service VLAN tag identifier (S-Tag), ``0x88A8``, is bound to
  :class:`~pcapkit.protocols.link.s_tag.S_Tag`, and the customer tag ``0x8100``
  to :class:`~pcapkit.protocols.link.c_tag.C_Tag`. Both subclass the now-abstract
  :class:`~pcapkit.protocols.link.vlan.VLAN`, which carries the shared tag
  layout; the split exists so that a Q-in-Q frame's two tags stay distinct in
  the parsed output. Fixing the shared ``read`` also fixed the DEI flag, which
  had been reported as ``bool(pcp)`` rather than read from its own bit.
* ``LinkType`` ``NULL``, ``LOOP`` and ``RAW`` carry bare IPv4 or IPv6, both of
  which pcapkit dissects. ``NULL`` and ``LOOP`` need their four-octet address
  family word skipped first, and ``RAW`` needs a version sniff.

Three follow-ups the above deliberately left alone:

* ``TransType`` 115 (``L2TP``) stays unbound, and the reason is now structural
  rather than incidental: it references :rfc:`3931`, i.e. L2TPv3 over IP, and
  **there is no** ``L2TPv3`` **class for it to point at**. What exists is
  :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`, the :rfc:`2661` v2 framing,
  reached over UDP 1701. So the binding waits on a v3 dissector, which is also
  the first member of the family to carry an
  :meth:`~pcapkit.protocols.protocol.Protocol.__index__` of its own -- 115
  being that index. :mod:`pcapkit.protocols.link.l2tp` records what v3 needs, and
  what ``L2F`` needs alongside it: the version nibble reading ``1`` selects L2F
  [:rfc:`2341`], a separate protocol, not an earlier L2TP.
* :class:`~pcapkit.protocols.link.ospf.OSPF` and the
  :class:`~pcapkit.protocols.link.l2tp.L2TP` family both live under
  :mod:`pcapkit.protocols.link` and so report ``layer == 'Link'``, although one
  is carried inside IP and the other inside UDP. Moving them would change their
  public import paths, so the misclassification is documented rather than
  fixed. It is inert for layer-limited extraction, since IPv4 and IPv6 terminate
  an ``internet`` extraction before either is reached.
* **Done.** :attr:`UDP.__proto__
  <pcapkit.protocols.transport.udp.UDP.__proto__>` pointed its HTTP ports at the
  version-identifying :class:`pcapkit.protocols.application.http.HTTP` while
  :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>` pointed
  the same ports at :class:`pcapkit.protocols.application.httpv1.HTTP`, an
  asymmetry that predated the 8080 entries. Both now bind the proxy, so a TCP
  segment's HTTP version is decided by its payload rather than asserted by its
  port number. It waited on
  `#800 <https://github.com/JarryShaw/PyPCAPKit/issues/800>`__, which replaced
  the proxy's trial-and-error guess with a positive identification: repointing
  ahead of that would have routed 231 real HTTP/1.1 fixture frames through a
  guess path that was known-wrong on non-HTTP input. The separate defect that
  ``http.HTTP``'s explicit ``version=`` path was unusable --
  `#447 <https://github.com/JarryShaw/PyPCAPKit/issues/447>`__ -- had already
  been fixed and was never part of this.

Beyond those, the gaps most likely to be met in a real capture are ICMP (1),
ICMPv6 (58) and IGMP (2) on the internet layer, all three of which have stubs;
and ``LINUX_SLL`` and ``LINUX_SLL2`` at the link layer, which every
``tcpdump -i any`` capture uses and which have no stub.

PCAPNG Support
--------------

**Done.** The builtin default engine parses PCAP-NG files;
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implements the format, with its
block and option enumerations under :doc:`pcapkit/const/pcapng`. This closes
the request in `#35 <https://github.com/JarryShaw/PyPCAPKit/issues/35>`__, which
the thread raised when only PCAP was supported.

Maybe Even Faster?
------------------

**Partly done.** The measured benchmark this section used to ask for now exists,
and acting on it cut extraction time on a 1117-frame HTTP capture by about 46%
with byte-identical output. Four things were wrong on the hot path, none of them
the ones the thread predicted:

* character-set detection was uncached, and accounted for 30% of an HTTP
  extraction -- 3011 :func:`chardet.detect` calls over 163 distinct
  bytestrings;
* every field of every protocol was copied through the generic
  :func:`copy.copy` machinery, 63207 times per extraction;
* :attr:`Field.length <pcapkit.corekit.fields.field.FieldBase.length>` recomputes
  :func:`struct.calcsize` on each read and was read two to four times per field;
* :meth:`Schema.__setattr__ <pcapkit.protocols.schema.schema.Schema.__setattr__>`
  re-entered itself once per field assigned.

Two predictions the profiling **contradicted**, recorded so nobody spends time on
them again: :class:`~pcapkit.corekit.infoclass.Info` construction -- the usual
suspect -- is 0.0% of its own cost and 4.4% of a parse, and the logging
integration is 0.03% even in the heaviest shape, since every call site is a lazy
``%s``. The IO-batching idea the thread proposed was never the bottleneck.

Of the three larger wins this section listed, all outside the parse path, one has
landed in full and the other two in part:

* **The flow dumper reopens its output file once per frame**
  (``pcapkit/dumpkit/pcap.py:120``). It no longer *also* rebuilds a whole
  :class:`~pcapkit.protocols.misc.pcap.frame.Frame` to obtain bytes it already
  holds: dropping that re-dissection was about 82% of the cost of a flow-traced
  extraction by itself, and the counterfactual that proposed it had left 330 of
  331 output files byte-identical. The reopen is what remains.
* **A datagram is submitted for every frame, fragmented or not**, because
  ``pcapkit/toolkit/pcap.py:53`` filters only on the *DF* flag -- so a capture
  with no fragments at all still produces one "datagram" per frame. Parsing its
  payload is no longer part of that cost:
  :meth:`~pcapkit.protocols.protocol.Protocol.analyze` used to run eagerly on
  each one, 86% of the IP-reassembly cost plus a 133 ms garbage-collection bill,
  and :attr:`Datagram.packet
  <pcapkit.foundation.reassembly.data.ip.Datagram.packet>` is now a
  :class:`~pcapkit.foundation.reassembly.data.data.Deferred` parsed on first
  read. Whether unfragmented frames should be emitted at all is the design
  question that is left, and it is worth settling deliberately.
* **Done.** Every option was parsed twice -- 2274 schema unpacks for 1137
  options, the pre-parse always discarded, about 15% of a PCAP-NG extraction.
  :class:`~pcapkit.corekit.fields.collections.OptionField` now reads only the
  base schema's type field to choose the option schema, rather than unpacking the
  whole base schema and throwing it away
  (``pcapkit/corekit/fields/collections.py:402-420``).

Two traps for anyone benchmarking this library. ``reassembly=True`` and
``trace=True`` are **no-ops** without ``ip=``/``tcp=``, so a benchmark that passes
only the switch measures nothing; and timing several capture shapes in one
process inflates them by up to 73%, so each shape wants its own interpreter.

Logging Integration
-------------------

**Done.** :mod:`pcapkit.utilities.logging` is no longer a single flat logger
with a hard-wired handler. It now provides:

- a **logger hierarchy** rooted at ``pcapkit``, with every module logging
  through its own child obtained from
  :func:`~pcapkit.utilities.logging.get_logger`, so that a subtree such as
  ``pcapkit.foundation.registry`` can be silenced independently of
  ``pcapkit.foundation.extraction``;
- **library-safe defaults** -- importing :mod:`pcapkit` attaches only a
  :class:`logging.NullHandler` and sets no level, leaving the destination and
  verbosity to the application. :envvar:`PCAPKIT_DEVMODE` still bootstraps the
  historical :obj:`sys.stderr` handler at :data:`logging.DEBUG`;
- a **runtime configuration API** --
  :func:`~pcapkit.utilities.logging.configure`,
  :func:`~pcapkit.utilities.logging.reset` and
  :func:`~pcapkit.utilities.logging.ensure_output` -- rather than a single
  environment variable read once at import;
- **levels chosen deliberately**. Registration bookkeeping across
  :mod:`pcapkit.foundation.registry` moved from ``info`` to ``debug``, since
  a library announcing its own registry entries is not news to its consumer;
  and the four :func:`print` calls that were marked
  ``# pylint: disable=logging-fstring-interpolation`` are now real logger
  calls;
- **debug coverage of the extraction path** -- extractor construction,
  engine selection and fallback, frame counts, cleanup, reassembly and
  flow-tracing setup -- so that ``DEBUG`` explains what PyPCAPKit did with a
  file without descending into per-field parsing.

See :doc:`pcapkit/utilities/logging` for the configuration recipes, including
the one-line restore of the pre-existing :obj:`sys.stderr` output.

One item remains wanted, called out there as deliberately out of scope:
:func:`pcapkit.utilities.warnings.warn` still reports every warning twice, once
through :mod:`logging` and once through :mod:`warnings`, so an application that
has routed :mod:`warnings` into :mod:`logging` sees each one of them twice.

New Engines
-----------

**Done, for both candidates.** ``engine='pypcapfile'`` selects
:class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile` and
``engine='pypcap'`` selects :class:`pcapkit.foundation.engines.pypcap.PyPCAP`;
each has a matching :mod:`pcapkit.toolkit` module
(:mod:`pcapkit.toolkit.pypcapfile`, :mod:`pcapkit.toolkit.pypcap`), a
``pyproject.toml`` extra (``PyPCAPFile``, which ``all`` includes, and
``PyPCAP``, which it deliberately does not -- see below), docs
under :doc:`pcapkit/foundation/engines/index`, and tests under
``tests/foundation/engines/`` and ``tests/toolkit/``. Both were verified
end-to-end against the sample captures: each agrees with the ``default`` engine
on frame count, per-record capture length, timestamp and Ethernet header.

Neither library, though, is usable straight from PyPI on a current Python, and
both of the following are worth knowing before reaching for them:

* **pypcapfile** -- the released 0.12.0 imports the ``imp`` module, removed in
  Python 3.12. Precisely, ``pcapfile/linklayer.py`` imports it at module scope
  and ``pcapfile.savefile`` imports ``linklayer``, so while a bare
  ``import pcapfile`` still succeeds on 3.12+, the two modules the engine
  actually needs raise :exc:`ModuleNotFoundError`. Upstream ``master`` (0.12.1,
  unreleased) has fixed this, and that is what the engine was verified against.
  The extra therefore installs a version that only works on Python 3.10 and
  3.11 until 0.12.1 is published.
* **pypcap** -- the 1.3.0 sdist (the only distribution; there has been no wheel
  since Python 2.7) ships a ``pcap.c`` pre-generated by Cython 0.29.32 and
  compiles it verbatim -- its :file:`setup.py` never invokes Cython. That
  generated C does not compile against the Python 3.12+ C API, and the cause is
  three independent CPython removals rather than one: ``ob_digit`` and
  ``PyThreadState.curexc_traceback`` went in 3.12, ``_PyLong_AsByteArray``
  gained a sixth parameter in 3.13, and ``PyDictObject.ma_version_tag`` went in
  3.14. **The ceiling is therefore Python 3.11**, measured: given
  :program:`libpcap`, the shipped ``pcap.c`` builds unchanged on 3.10 and 3.11
  and fails on 3.12 and 3.14. Regenerating it needs Cython **3.0+** -- no
  0.29.x release, including the last, emits 3.12-compatible C.

  Separately, its :file:`setup.py` consults neither ``CFLAGS``/``LDFLAGS`` nor
  :program:`pkg-config`; it searches a fixed prefix list (:file:`/usr`,
  ``sys.prefix``, :file:`/opt/libpcap*`, :file:`../libpcap*`,
  :file:`../wpdpack*`, the macOS SDKs). ``/opt/homebrew`` is absent from that
  list, and Homebrew's ``libpcap`` is ``keg_only :provided_by_macos`` so it is
  never symlinked into a searched prefix either -- meaning
  ``brew install libpcap`` on the arm64 macOS runners would **not** have fixed
  the original failure, on either count. It builds once :program:`libpcap` is
  visible under ``sys.prefix`` *and* the interpreter is 3.11 or older.

  That is a packaging problem upstream rather than an engine problem -- and
  upstream is unmaintained, with no code commit since the 1.3.0 release and its
  Python 3.12 issue (`pynetwork/pypcap#116
  <https://github.com/pynetwork/pypcap/issues/116>`__) open and uncommented
  since May 2024. It does mean ``pip install pypcapkit[PyPCAP]`` can fail to
  build. Since there is no wheel to fall back on, the extra is kept **out of**
  ``all``: otherwise ``pip install pypcapkit[all]`` would demand a compiler and
  the libpcap development files from every user, and it broke the docs, conda
  and release workflows -- all of which install ``.[all]`` -- on the macOS
  runner, where :file:`pcap.h` is present but no ``libpcap.dylib`` is.

  This is now solved, though not by changing the ``PyPCAP`` extra. `pcap-ct
  <https://pypi.org/project/pcap-ct/>`__ re-implements the ``pypcap`` API in pure
  Python over :mod:`ctypes`, and it is wired up as a **separate engine**,
  :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`, selected with
  ``engine='pcap_ct'`` and installed with ``pip install pypcapkit[PCAP_CT]``. It
  works on every supported interpreter, verified on 3.10 and 3.14.

  A separate engine rather than a second backend because the two are **mutually
  exclusive**: both distributions own the import name ``pcap``, and with both
  installed ``pcap-ct`` wins the import while upstream's extension module is
  shadowed and unreachable. Each engine detects which backend it actually got and
  says so, rather than one ``engine=`` string silently meaning two different
  implementations.

  Two caveats remain. Both distributions are still beta releases, and ``pcap-ct``
  targets the ``pypcap`` 1.2.3 API -- within what this engine uses, but worth
  knowing. And despite the `libpcap <https://pypi.org/project/libpcap/>`__ wheel
  bundling prebuilt binaries, a runtime ``libpcap`` shared library is still
  required: that wheel's published configuration sets ``LIBPCAP = None``, which
  sends the loader to ``find_library("pcap")``. No compiler and no
  :file:`pcap.h` are needed; a ``libpcap.so.1`` is.

Both engines support less than the ``default`` engine does, deliberately and
noisily: `pypcap`_ performs no protocol dissection, so it disables reassembly
*and* flow tracing; `pypcapfile`_ has no IPv6 decoder, so it disables IPv6
reassembly while keeping IPv4 and TCP. Each gap is announced through an
:class:`~pcapkit.utilities.warnings.AttributeWarning` or an outright exception
rather than by silently returning nothing --
:doc:`pcapkit/foundation/engines/index` tabulates them.

Adding a further engine no longer means adding handler methods to
:class:`~pcapkit.foundation.extraction.Extractor`, as the thread describes: the
engine interface has been refactored since. A new engine subclasses
:class:`pcapkit.foundation.engines.engine.Engine` and implements just two
methods, :meth:`~pcapkit.foundation.engines.engine.Engine.run`
and :meth:`~pcapkit.foundation.engines.engine.Engine.read_frame`; subclassing
registers it automatically. See :doc:`ext` for a worked example. What does
still apply is the unified auxiliary tools in :mod:`pcapkit.toolkit`, where
each engine has a matching module.

.. _pypcap: https://github.com/pynetwork/pypcap
.. _pypcapfile: https://github.com/kisom/pypcapfile

Test Cases
----------

**Largely done.** There is now a systematic test suite under ``tests/`` -- 105
modules matching ``test_*.py`` -- and it runs in CI against Python 3.10
through 3.14, plus an allowed-to-fail 3.15 leg, per
``.github/workflows/unit-tests.yml``.

The suite is split by what a test needs rather than by what it covers, and
``tests/_tiers.py`` enforces the split. The **unit** tier may read only
captures committed to the repository; the **fixture-dependent** tier -- which
is ``tests/integration/`` together with every ``*_runtime.py`` and
``*_regression.py`` module -- may also read the generated sample captures.
Those samples are not tracked in git, so
``examples/generators/make_samples.py`` (``make samples``) rebuilds them from
source, and the tier guard raises rather than letting a unit-tier module
quietly depend on a file that may not exist.

What remains wanted is **coverage rather than infrastructure**: the protocols and
the registered-but-unhandled type codes listed above have no tests because they
have no implementation yet.

The original ask also included **shipping the suite**, and that is now a
deliberate decision rather than an omission. ``tests`` is excluded from the wheel
by ``[tool.setuptools.packages.find]`` in ``pyproject.toml``; the sdist does carry
all 105 modules, so a distribution packager building from source has them. The
wheel stays lean because the suite could not run from an installed package
anyway: the generated sample captures are not shipped, and ``tests/_tiers.py``
resolves paths from a repository root that an installed package does not have.
Anyone wanting to run the tests wants the repository, which is where they are.

Reassembly Beyond IP and TCP
----------------------------

**Still open**, and newer than the rest of this page --
:doc:`pcapkit/foundation/reassembly/index` covers three protocols and no more.
IPv4 and IPv6 share the :rfc:`791` procedure, and TCP uses the :rfc:`815`
hole-descriptor algorithm, which does handle out-of-order and overlapping
segments. SCTP has nothing: a user message split across DATA chunks is never put
back together, and ``sctp`` appears nowhere in
:mod:`pcapkit.foundation.reassembly` at all.

What that costs is concrete. The dissector already exposes everything a
reassembler needs, on
:class:`~pcapkit.protocols.data.transport.sctp.DATAChunk` -- ``tsn``,
``stream_id``, ``stream_seq``, ``ppid``, ``data``, and ``flags.B`` and
``flags.E`` for the beginning and ending fragment bits -- and nothing reads
those two bits outside the construction path. So each fragment is dispatched on
its own PPID as though it were a whole PDU, and a registered upper layer is
handed half a message. Two related holes compound it: only the *first* DATA
chunk of a bundle is dispatched at all, and I-DATA [:rfc:`8260`], chunk type 64,
is not dissected -- so the MID and FSN fields that exist precisely to make
interleaved reassembly tractable are never parsed, and an I-DATA-only packet
yields no payload whatsoever. FORWARD TSN (192) and I-FORWARD-TSN (194) are
likewise unhandled, so partial-reliability stream advancement is invisible.

Writing the reassembler is the smaller half of the job. It would go at
``pcapkit/foundation/reassembly/sctp.py``, subclass
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` and implement two
methods,
:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly` and
:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.submit`. Registering
it, though, is currently inert:
:meth:`~pcapkit.foundation.extraction.Extractor.register_reassembly` accepts any
protocol name, while
:class:`~pcapkit.foundation.extraction.Extractor` only ever instantiates the
three it names literally, and
:class:`~pcapkit.foundation.reassembly.ReassemblyManager` is a fixed-field
container with no room for a fourth. Making SCTP reachable therefore also means
touching that manager and its read-side twin, the construction branch in
:class:`~pcapkit.foundation.extraction.Extractor`, one adapter per engine in
:mod:`pcapkit.toolkit`, the call site in each of those engines, and
:func:`~pcapkit.interface.core.reassemble`. Generalising that wiring so a
registered reassembler is actually used is worth doing on its own account, and
would make the fourth protocol cheaper than the third rather than dearer.

Two smaller items in the same subsystem:

* **Flow tracing is TCP only**, and blocked on the same generalisation --
  :class:`~pcapkit.foundation.traceflow.TraceFlowManager` holds a single field,
  so UDP, SCTP and IP conversation tracing have nowhere to go.

  It no longer *treats each direction of a connection as a separate flow*,
  though, and RST is no longer missing from
  :class:`~pcapkit.foundation.traceflow.data.tcp.Packet`. :meth:`TCP.make_bufid
  <pcapkit.foundation.traceflow.tcp.TCP.make_bufid>` orders the two endpoints
  canonically, so both halves of a conversation reduce to one buffer ID, one
  label and one output file, and
  :class:`~pcapkit.foundation.traceflow.data.tcp.Index` reports ``forward`` and
  ``reverse`` alongside ``index`` so per-direction ordering stays recoverable.
  This is the default; ``bidirectional=False``
  (``trace_bidirectional=False`` on
  :class:`~pcapkit.foundation.extraction.Extractor`,
  :func:`~pcapkit.interface.core.extract` and
  :func:`~pcapkit.interface.misc.follow_tcp_stream`) restores the older
  per-direction behaviour.

  What ends a bidirectional flow is worth stating, because the obvious answer is
  wrong. A teardown -- a FIN from each endpoint, or a RST from either -- is
  *recorded* but does not finalise the flow: the four-way close of
  :rfc:`9293#section-3.6` is FIN, ACK, FIN, ACK, so the final acknowledgement
  arrives after the second FIN, and finalising on that FIN drops the ACK from the
  flow and lets it open a fresh buffer under the same canonical buffer ID -- which
  a later connection reusing those endpoints then merges into. Duplicates of that
  ACK defeat any rule that tries to name the last packet of the exchange. So the
  flow is finalised only by proof that nothing more can arrive: a new connection's
  SYN on the same endpoints, or the end of the capture, via
  :meth:`TraceFlow.finish
  <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.finish>`. Distinguishing
  that SYN from the peer's SYN-ACK is what the recorded teardown is for.

  One case remains undecided rather than solved: a capture that *starts* in the
  middle of a connection, sees no teardown, and then has its endpoints reused. The
  reuse is indistinguishable from a continuation without the ACK flag on
  :class:`~pcapkit.foundation.traceflow.data.tcp.Packet`, which would make
  ``syn and not ack`` a definitive new-connection test on its own.

  **The application layer is wired into flow tracing** as well, though it is a
  capability rather than a parse to postpone: flow tracing buffered no payload at
  all, so there was no second parse to defer. Of the two ways of getting one, the
  tracer **delegates to**
  :class:`~pcapkit.foundation.reassembly.tcp.TCP` rather than growing a
  per-direction payload buffer of its own. A buffer that concatenated payloads in
  capture order would be silently wrong on the first retransmission or reordered
  segment, where the :rfc:`815` hole-descriptor algorithm already in the
  reassembler is not -- so
  :class:`~pcapkit.foundation.traceflow.data.tcp.Packet` carries the four segment
  fields (``seq``, ``ack``, ``header``, ``payload``) that reassembler needs, and
  the tracer hands each traced segment straight to it.

  :attr:`Index.packet <pcapkit.foundation.traceflow.data.tcp.Index.packet>` then
  holds one reassembled datagram per direction, and postpones twice: reading it is
  what flushes the flow's reassembler, and each datagram's own
  :attr:`~pcapkit.foundation.reassembly.data.tcp.Datagram.packet` is parsed later
  still, through the same
  :class:`~pcapkit.foundation.reassembly.data.data.Deferred` arrangement the
  reassembly side uses. It is **opt-in** -- ``analyse=True``, or
  ``trace_analyse=True`` on :class:`~pcapkit.foundation.extraction.Extractor`,
  :func:`~pcapkit.interface.core.extract` and
  :func:`~pcapkit.interface.misc.follow_tcp_stream` -- because buffering every
  traced payload is a cost tracing does not otherwise pay, and tracing's
  per-packet cost is something this package has deliberately driven down. It is
  unavailable on the ``pyshark`` engine, which reports dissected fields rather
  than the octets behind them, and which for the same reason has no reassembly
  adapter at all; asking for it there warns and falls back.
* **Timing a partial datagram out** is implemented, for IP.
  :meth:`Reassembly.expire
  <pcapkit.foundation.reassembly.reassembly.ReassemblyBase.expire>` abandons a
  buffer whose first-arriving fragment is older than
  :attr:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase.timeout`
  seconds, and the buffer models carry the timestamp that makes it possible.

  The clock is the **capture's own timestamps**, not the host's: an offline
  parser has no other notion of time passing, and keying on
  :func:`time.time` would make the same file reassemble differently on every
  run. A fragment being handed over is the only evidence capture time has
  advanced, so that is when the sweep happens -- which means the clock advances
  only while the reassembler is being fed. For IPv4 and TCP that is nearly every
  frame of the protocol; for IPv6 it is only the fragments, so an IPv6 buffer
  that stalls with no further fragment behind it is reported as
  :attr:`~pcapkit.foundation.reassembly.data.data.Completion.PARTIAL` rather
  than
  :attr:`~pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT`. That is
  the honest answer, since the capture never shows the deadline passing; feeding
  every frame's timestamp to every enabled reassembler would close the gap and
  is worth doing on its own account.

  On the numbers: the 15 seconds this page used to attribute to :rfc:`791` is
  that RFC's *initial* timer setting, a lower bound which
  ``TIMER <- MAX(TIMER,TTL)`` then raises toward the 4.25-minute TTL ceiling --
  not a deadline. :rfc:`1122#section-3.3.2` supersedes the scheme outright
  ("The reassembly timeout value SHOULD be a fixed value, not set from the
  remaining TTL... between 60 seconds and 120 seconds"), so IPv4 uses 60
  seconds, agreeing with the 60 :rfc:`8200#section-4.5` mandates for IPv6.
  **TCP is left with no timeout at all**, since no specification gives stream
  reassembly a deadline and an idle connection is ordinary rather than
  pathological; ``timeout`` enables one on request.

  Two related things are *not* done. :rfc:`8200#section-4.5` and
  :rfc:`1122#section-3.3.2` both want an ICMP Time Exceeded sent on expiry when
  the offset-zero fragment has been received; a parser sends nothing, so the
  condition is only reported in the log record. And the memory motive is
  narrowed rather than removed -- an in-flight IP datagram identifier still
  holds a fixed 72 KiB of preallocated space, but now for at most the timeout's
  worth of capture time rather than for the life of the
  :class:`~pcapkit.foundation.extraction.Extractor`.

Reassembly is also unavailable on some engines rather than merely slower, which
is worth knowing before benchmarking against them: ``pyshark``, ``pypcap`` and
``pcap_ct`` disable it entirely, and ``pypcapfile`` disables the IPv6 half of it.
:doc:`pcapkit/foundation/engines/index` tabulates that.

Checksum and Integrity Verification
-----------------------------------

Eight protocols parse a checksum or CRC field —
:class:`~pcapkit.protocols.internet.hip.HIP`,
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT`,
:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`,
:class:`~pcapkit.protocols.link.ospf.OSPF`,
:class:`~pcapkit.protocols.transport.sctp.SCTP`,
:class:`~pcapkit.protocols.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.udp.UDP` — and exactly one of them checks
whether the value is *right*:
:attr:`SCTP.checksum_valid <pcapkit.protocols.transport.sctp.SCTP.checksum_valid>`.
For the other seven the field is recorded and never questioned, so a corrupted
capture parses as cleanly as an intact one.

**These are two different problems and they want separating**, because only one
of them is cryptographic and the distinction decides what is actually hard.

**The one's-complement Internet checksum**, which covers IPv4's header, TCP, UDP,
ICMP/ICMPv6 and OSPF, needs no cryptography at all — it is sixteen-bit addition
with end-around carry, and implementing it is an afternoon. What blocks it is the
**IP pseudo-header**: the TCP, UDP and ICMPv6 checksums are computed over source
and destination addresses, the protocol number and the payload length, all of
which live in the *enclosing* layer. So verification needs a parsed protocol to
reach back to its parent, which is a structural question about
:class:`~pcapkit.protocols.protocol.Protocol` rather than an arithmetic one.
That is precisely why SCTP came first and is not evidence the rest are easy:
:rfc:`9260#section-6.8` defines its CRC32c over the common header and chunks with
the checksum field zeroed and **no pseudo-header**, so it can be verified from
the SCTP packet alone. Note also that SCTP's CRC32c is a hand-rolled lookup table
in :mod:`pcapkit.protocols.transport.sctp`, not a library call, so it is not
precedent for a dependency either.

**The cryptographic integrity checks** are where the :mod:`cryptography`
dependency — introduced for ESP — genuinely buys something new, and half of that
is already done. :class:`~pcapkit.protocols.internet.esp.ESP` **already verifies
its ICV** when a Security Association is supplied, and deliberately reports a
failure rather than raising, so a forged packet still parses and says so. What is
*not* done is **HIP**: its ``HIP_MAC``, ``HIP_MAC_2``, ``RVS_HMAC`` and
``RELAY_HMAC`` parameters, and its ``HIP_SIGNATURE`` and ``HIP_SIGNATURE_2``
parameters, are parsed into their data models and never checked against the
packet. Verifying them needs a keying context in the shape ESP already
established through :mod:`pcapkit.corekit.context`, which is the reusable part of
the design rather than something to invent.

All three of the policy questions this raised have been settled by the repo
owner, and each lands on a precedent the library already has:

* **Verification is opt-in.** Checksumming every packet costs real time on a
  large capture, and `Maybe Even Faster?`_ above is a standing concern, so it is
  a flag rather than unconditional behaviour.
* **A wrong checksum is a warning, not a hard failure, and the outcome is
  recorded on the protocol class.** The warning belongs in
  :class:`~pcapkit.utilities.warnings.ProtocolWarning`, and the recording has an
  exact precedent in :class:`~pcapkit.protocols.internet.esp.ESPStatus`: an
  enumeration of outcomes carried on the parsed result, so a caller can ask
  after the fact rather than having to have been capturing warnings at the
  time. That distinction matters — a warning is for the human watching, and the
  recorded status is for the program. Note ESP's enum also has a member for "the
  expected state for a capture taken without keys, and is **not** an error",
  which is the shape the offload case below wants.
* **The IP pseudo-header gets a pseudo-protocol class.** Rather than giving a
  parsed protocol a back-reference to its parent, the pseudo-header becomes a
  first-class thing in its own right, defined once for the IP family and used by
  **both** the parsing and the constructing path. That is the better answer:
  a back-reference only helps verification, while a pseudo-header class is also
  what the construction side needs in order to *emit* a correct checksum, and
  the two paths then share one definition instead of agreeing by coincidence.

One case still wants a decision at implementation time, since it is about
wording rather than design: **checksum offload**. A capture taken on the sending
host routinely contains checksums the NIC had not computed yet, so the field is
zero or garbage on the wire and "invalid" is the wrong word for it. Whatever
status enumeration this grows should be able to say *not computed* distinctly
from *wrong*, or it will cry wolf on the commonest capture there is —
:class:`~pcapkit.protocols.internet.esp.ESPStatus`'s ``NO_SA`` member is the
model for how to spell "expected, not an error".

Sequenced for **wave 2 or 3**. The cryptographic half could be done sooner since
ESP has already laid the groundwork, but the checksum half genuinely wants the
parent-access question answered first, and that is worth doing deliberately
rather than as a side effect of a checksum patch.

Release Plan — 1.5.0 in Two Steps
---------------------------------

The version in :mod:`pcapkit` is ``1.5.0b3``, and the release is sequenced
against the waves above in two deliberate steps:

#. **A beta — ``1.5.0b1`` — when wave 1's remaining issues are closed.**
   *Done.* Wave 1's feature work had landed already; what remained was the
   defect tail in `the issue tracker
   <https://github.com/JarryShaw/PyPCAPKit/issues>`__, and closing it earned a
   beta rather than a final release, because the consistency sweep below had not
   run yet and was expected to find things. It has since found some: the
   ipv6-route packing test was added only because the fix it covers had shipped
   untested, and the
   :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route` Source-Route
   round-trip defect was found sideways while writing it.
#. **The official ``1.5.0`` when the post-wave-1 consistency sweep is done.** The
   sweep is described under `Delivery Sequence`_ below — prose against code,
   missing tests, unaligned changes, and packet formats against the
   specifications. Its whole point is to find what one-at-a-time defect work
   does not, so shipping a final release before it has run would be shipping
   ahead of the evidence.

**The version string is the release button, so it is worth knowing exactly what
each step does before editing it.** ``.github/workflows/create-release.yml`` is
version-driven rather than tag-driven: its ``version_check`` job reads
``pcapkit.__version__`` directly, derives ``PCAPKIT_PRERELEASE`` from
``packaging.version.Version(...).is_prerelease``, and picks the Anaconda label
from the same test.

Worth spelling out how that workflow is *reached*, because reading its ``on:``
block alone suggests it is not reachable from an ordinary commit at all — it
lists only ``push`` on ``v*`` tags and a ``workflow_run``. The chain is:

.. code-block:: text

   push to main  ->  "Vendor Update"   (cron-vendor.yml, which triggers on push to main)
                 ->  "Create Release"  (workflow_run, on Vendor Update completing)

Every publishing job — ``github``, ``tag``, ``pypi``, ``conda`` — is gated on
``startsWith(github.ref_name, 'v') || PCAPKIT_TAG_EXISTS == 'false'``. That gate
is why ordinary commits do not publish: ``Create Release`` runs on each one, but
the tag for the current version already exists, so all four jobs skip. Changing
the version string is what makes ``PCAPKIT_TAG_EXISTS`` false, and the next push
then tags and publishes. So:

.. list-table::
   :header-rows: 1
   :widths: 20 20 20 40

   * - version
     - prerelease
     - conda label
     - GitHub release
   * - ``1.5.0a1`` (shipped earlier)
     - yes
     - ``dev``
     - marked prerelease
   * - ``1.5.0b1`` (step 1)
     - yes
     - ``dev``
     - marked prerelease
   * - ``1.5.0b3`` (**current**)
     - yes
     - ``dev``
     - marked prerelease
   * - ``1.5.0`` (step 2)
     - **no**
     - **``main``**
     - full release

Both steps publish to PyPI — the ``pypi`` job carries no prerelease gate — but a
beta is only installable with ``pip install --pre``, so it reaches people
who ask for it and nobody else. The consequential change is at step 2, where the
Anaconda label flips from ``dev`` to ``main``. Neither step needs any change to
the workflow itself; editing the version string is the whole of it, which is
precisely why it should be its own commit rather than a line folded into
something else.

Delivery Sequence
-----------------

The items above are ordered by subject rather than by when anyone intends to do
them. This section records the intended **order**, so that a contributor can see
what is being worked on, what is queued behind it, and — more usefully — which
items are queued because they *depend* on something rather than merely because
nobody has started them.

It is a sequencing note, not a commitment: nothing here is claimed, and an item
being in a later wave is not a reason to leave it alone if you want it now. Say
so in the `discussion thread
<https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ and it moves.

**Wave 1 — done or in flight.** The Mobility Header registry completion, the
protocol bindings (FTP-DATA, HTTP-alt, OSPF, L2TP, the 802.1ad S-Tag), the
:class:`~pcapkit.protocols.link.vlan.VLAN` C-Tag/S-Tag split, the option
round-trip coverage harness, and reassembly's :rfc:`8200` timeout with
bidirectional flow tracing. What remains of wave 1 is defect work, tracked in
`the issue tracker <https://github.com/JarryShaw/PyPCAPKit/issues>`__ rather than
here.

**Wave 2 — the protocol pairs that want a shared abstract base**, per `More
Protocols, More!!!`_ above: **ICMP with ICMPv6**, **TLS/SSL with DTLS**, and
``LINUX_SLL`` with ``LINUX_SLL2``, plus **IGMP** on its own. These are grouped
because the shared-base question is the design work and doing either half of a
pair alone would answer it twice. ``LINUX_SLL`` matters out of proportion to its
size: every ``tcpdump -i any`` capture uses it, and neither variant has even a
stub.

**Wave 3 — the remaining protocols** from the same list, taken three or four at a
time. QUIC, DSL, FDDI and ISDN come last: QUIC because it is really HTTP/3 over a
new transport and wants that settled first, the other three because a capture in
the wild is rare enough that the work buys little until the commoner protocols
are in.

**Queued behind wave 2 — the Mobility Header sub-layer registry.** Several
mobility options carry a payload belonging to another protocol, and those
payloads want carrying as :class:`~pcapkit.protocols.misc.raw.Raw` through a
per-payload registry rather than as bare :obj:`bytes` — see `Mobility Header`_
above, which describes the payloads in question and why a registry of their own
is wanted instead of
:meth:`~pcapkit.protocols.protocol.Protocol._decode_next_layer`. It is
sequenced *after* wave 2 rather than by preference: the multicast options embed
:rfc:`3810` MLD, which rides in **ICMPv6**, and :rfc:`3376` **IGMP** records —
both wave 2 deliverables. Landing the registry first would give a dispatch table
with nothing but ``Raw`` to register. The counter-argument is real though, and
worth weighing rather than dismissing: changing the parsed shape from
:obj:`bytes` to ``Raw`` is the disruptive half, since it changes what existing
captures dump to, so there is a case for taking that churn early and registering
dissectors later. The third format, the :rfc:`6088` traffic selectors of
:rfc:`6089` and :rfc:`7222`, has no wave at all — it is a registry of its own and
nobody has claimed it.

**Wave 2 or 3 — per-entry coverage of the option and parameter registries.** The
option, parameter, block and frame registries are *enumerated* today but not
*implemented* throughout: a code can be registered, and named, and still have no
working per-entry read/make pair behind it. Measured against the eighteen
families :file:`examples/generators/options.py` walks, **327 codes are
registered and 59 of them do not round-trip** — roughly one in six. The goal of
this item is to close that to zero for every code whose format is actually
specified.

Where the gap sits, from ``EXPECTED_FAILURES`` in
:file:`tests/protocols/test_option_roundtrip_unit.py`:

.. list-table::
   :header-rows: 1

   * - Family
     - Not round-tripping
   * - ``pcapng-option``
     - 30
   * - ``tcp-mptcp``
     - 8
   * - ``ipv4-option``
     - 6
   * - ``hip-parameter``
     - 4
   * - ``pcapng-block``
     - 3
   * - ``tcp-option``, ``pcapng-secrets``
     - 2 each
   * - ``hopopt-option``, ``ipv6-opts-option``, ``ipv6-route-type``, ``httpv2-frame``
     - 1 each

Two things to be precise about before anyone starts. First, **"does not
round-trip" is not the same as "unimplemented"** — the 59 are a mix, and at
least one (``ipv6-route-type/RPL_Source_Route_Header``) is an implemented case
carrying a tracked defect rather than a missing implementation. The first task
is to split that list into *missing*, *defective* and *deliberately deferred*,
because the three want different work. Second, ``pcapng-option``'s 30 is half
the total on its own, so it is the item that decides whether this is one wave's
work or several; it deserves sizing before the rest.

This is deliberately **not** the same request as the ``__proto__`` dispatch
registries. Those name whole protocols, so closing a gap there means
implementing a dissector — bounded by protocol work that already has its own
waves above. The option and parameter registries are per-entry formats inside
protocols that already exist, so the work is self-contained and does not wait on
anything. Their enumerating harness already exists and already fails when a
registered code has no case, which is how these 59 are known at all; what is
missing is the implementations behind the codes, not the accounting of them.
:file:`tests/protocols/test_dispatch_registry_unit.py` gives the ``__proto__``
family the same accounting for the separate question of whether a registered
protocol's dispatch reaches it.

**Between wave 1 and wave 2 — a library-wide consistency sweep.** Wave 1 closed
by clearing defects one at a time, each found because something else was being
worked on nearby. That is a poor way to find the rest of them, so before wave 2
starts the library gets swept deliberately, in five strands:

* **Prose against code.** Docstrings, the README, and inline comments checked
  against what the code now does. Wave 1 produced three separate cases of a
  docstring outliving the thing it described — one of them survived the fix that
  invalidated it by under a minute — so this is a known failure mode rather than
  a hypothetical. Includes the rule that a docstring names the real defining
  module rather than the re-export.
* **Missing tests.** Not coverage percentage, which says nothing useful here, but
  named gaps: registry entries with no round-trip case, error paths that no test
  reaches, and behaviour asserted only in prose. The option round-trip harness
  already enumerates its own coverage and fails when a registered code has no
  case; the sweep asks which *other* registries deserve the same treatment.
* **Unaligned changes.** Drift where one half of a pair moved and the other did
  not — a schema whose data model disagrees with it, a maker whose annotation
  admits what its schema cannot hold, an ``EXPECTED_FAILURES`` entry naming a
  case that no longer fails. Several wave 1 defects were exactly this shape.
* **Packet formats against the specifications.** The most valuable strand, and
  the one with the clearest evidence behind it: reading the RFC field-by-field
  against the schema is what produced
  `#472 <https://github.com/JarryShaw/PyPCAPKit/issues/472>`__ — two HIP
  parameters sizing their list entries at one octet where :rfc:`5770` §5.4 and
  :rfc:`7402` §5.1.2 specify sixteen bits — and the same method then *cleared*
  fourteen further
  ``EnumField(length=1)`` sites in the same file against :rfc:`7401`,
  :rfc:`8002`, :rfc:`8003`, :rfc:`5770` and :rfc:`6078`. It both finds real
  defects and retires suspicion, which is why it is worth doing exhaustively
  rather than opportunistically.
* **Duplicated logic that wants a shared module.** The same method or the same
  arithmetic written out in several protocols, where one definition would do.
  This strand has the sharpest evidence of the five, because duplication here has
  already *caused* defects rather than merely offended tidiness:

  - `#487 <https://github.com/JarryShaw/PyPCAPKit/issues/487>`__ existed because
    ``IPv6_Route.make()`` computed ``Hdr Ext Len`` in **two** branches with two
    different wrong units, and the read side computed the inverse in a third
    place with a fourth. The fix was not new arithmetic but one helper per
    direction, each documenting the :rfc:`8200#section-4.4` unit and saying what
    its counterpart is.
  - `#483 <https://github.com/JarryShaw/PyPCAPKit/issues/483>`__ was the scapy
    toolkit adapter passing a fragment offset unscaled where every sibling
    adapter scaled it. Five adapters each restate the same field mapping, so a
    convention that holds in four and breaks in the fifth is invisible until a
    capture is wrong.

  So the strand is not a style pass. Look for arithmetic that encodes a wire
  unit, field-mapping tables restated per engine, and guards of the same shape
  repeated per registered type — and where extraction is not worth it, say so
  with the reason rather than leaving the duplication unexplained. Note also that
  two candidates may look alike and differ deliberately: TCP and IP reassembly
  resolve overlaps in *opposite* directions because :rfc:`791` and :rfc:`9293`
  §3.10 specify opposite resolutions, so "these two functions are nearly
  identical" is a question to answer against the specification, not a defect on
  its face.

The sweep's output is **verified issues, not a list of suspicions** — each entry
reproduced before it is filed, with the reproduction in the issue. An audit that
files what it merely suspects transfers the work rather than doing it, and this
project has already had to correct a finding whose count and whose diagnosis were
both wrong when re-derived.

**Queued for wave 2 or 3 — checksum and integrity verification.** See `Checksum
and Integrity Verification`_ above. It splits in two, and the halves are not
equally blocked: the cryptographic half (HIP's ``HIP_MAC``/``RVS_HMAC``/
``RELAY_HMAC`` and its two signature parameters) could start whenever, since
:class:`~pcapkit.protocols.internet.esp.ESP` has already established both the
keying-context channel and the report-rather-than-raise policy. The
one's-complement half (IPv4, TCP, UDP, ICMP/ICMPv6, OSPF) needs the IP
pseudo-header, and the owner has settled how: a **pseudo-protocol class** for the
IP family, serving both the parsing and the constructing path, rather than a
back-reference from a parsed protocol to its parent. So that half is no longer
blocked on an open design question -- it is blocked only on someone defining that
class, which is a bounded piece of work and the natural first step.
