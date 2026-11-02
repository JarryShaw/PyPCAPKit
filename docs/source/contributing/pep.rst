Help Wanted
===========

.. important::

   This page is the maintained copy of the project's enhancement proposals, kept
   in step with the code. The `discussion thread
   <https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ holds them as they
   were first raised; here an implemented proposal is described as implemented,
   and only genuinely open work is asked for. Please leave notes in the thread
   rather than against this page.

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

* Link Layer: DSL, EAPOL, FDDI, ISDN, NDP, PPP
* Internet Layer: ECN, Shim6
* Transport Layer: RSVP
* Application Layer: BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT, NNTP,
  NTP, ONC/RPC, POP, QUIC, RIP, RTP, SIP, SMTP, SNMP, SSH, Telnet,
  XMPP

Several of these come in pairs that want a shared abstract base rather than two
independent implementations, in the way
:class:`~pcapkit.protocols.internet.ip.IP` and
:class:`~pcapkit.protocols.internet.icmp.ICMP` already cover their families:
IP and IPsec, and TLS/SSL with DTLS. **Done** for TLS/SSL
with DTLS: :class:`~pcapkit.protocols.application.sslv2.SSLv2`,
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.dtls.DTLS` share
:class:`~pcapkit.protocols.application.ssl.SSL` as their base by name, and only
TLS and DTLS share its record layer -- see the `DTLS`_ section
below. Neighbor Discovery (:rfc:`4861`, the ``NDP`` above) and Multicast
Listener Discovery (:rfc:`9777`), both carried in ICMPv6, are not implemented.
:class:`~pcapkit.protocols.link.vlan.VLAN` is the closer precedent for a pair
whose *layout* is identical -- it holds the whole of the tag, and
:class:`~pcapkit.protocols.link.c_tag.C_Tag` and
:class:`~pcapkit.protocols.link.s_tag.S_Tag` add only how each names itself.

.. note::

   Some of these have an empty, protocol-named file under a
   ``NotImplemented`` folder. **Those files are not a roadmap.** They are
   scratch reminders, so a stub's presence does not mean a protocol is planned or
   claimed, and its absence does not mean the protocol is unwanted:
   ``QUIC`` has no stub and is on the list above,
   while **NGAP** has none either and is implemented. Take this page as the
   record and ignore the folder.

SCTP
~~~~

**Done.** :class:`~pcapkit.protocols.transport.sctp.SCTP` is a first-class
transport layer protocol implemented per :rfc:`9260`: the common header, every
chunk type, chunk parameter and error cause the RFC defines, and CRC32c checksum
verification.

One note on how it differs from its siblings. The next layer is dispatched
on the DATA chunk's *payload protocol identifier* through
:func:`~pcapkit.foundation.registry.protocols.register_sctp`, not on port
numbers, so :func:`~pcapkit.foundation.registry.protocols.register_apptype`
deliberately does not fan out to it.

What is still wanted is the registered-but-unimplemented type codes. IANA
registers considerably more than :rfc:`9260` defines, and the surplus falls
through to the generic handlers rather than failing the extraction -- so a
capture using one parses, but yields an opaque chunk instead of its fields.
That is true of many of the registered chunk types, chunk parameters and error
causes; :doc:`/pcapkit/const/sctp` lists them all.

The other thing wanted for SCTP is reassembly, which
:mod:`pcapkit.foundation.reassembly` has only for IP, TCP and DTLS handshake
messages -- see `Reassembly Beyond IP and TCP`_ below, since it needs work in
:mod:`pcapkit.foundation` rather than in the protocol.

ESP
~~~

**Done.** :class:`~pcapkit.protocols.internet.esp.ESP` parses without keys, and
decrypts when a Security Association is supplied through the protocol keyed
:mod:`pcapkit.corekit.context` channel.

What is still wanted there is wider algorithm coverage. The enumerations
under :doc:`/pcapkit/const/esp` --
:class:`~pcapkit.const.esp.cipher.Cipher` and
:class:`~pcapkit.const.esp.integrity.Integrity` -- carry every transform IANA has
registered, but :data:`~pcapkit.protocols.internet.esp.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.INTEGRITY_SUITES` apply only a few of
them, the no-ops ``ENCR_NULL`` and ``NONE`` among them. So the real coverage is
AES-CBC and AES-GCM at every tag length for encryption, and HMAC-SHA1-96 plus
the :rfc:`4868` HMAC-SHA2 truncations for integrity.

Not implemented, roughly in the order a capture is likely to want them:
AES-CTR [:rfc:`3686`], AES-CCM at every tag length [:rfc:`4309`],
ChaCha20-Poly1305 [:rfc:`7634`], AES-XCBC-MAC-96 [:rfc:`3566`], AES-CMAC-96
[:rfc:`4494`], the AES-GMAC family and its ``ENCR_NULL_AUTH_AES_GMAC``
counterpart [:rfc:`4543`], and then the Camellia, implicit-IV [:rfc:`8750`] and
MGM [:rfc:`9227`] families. Extended Sequence Numbers are not implemented
either, and are the one item on this list that is not simply a table entry: the
high-order 32 bits are never transmitted, so recovering them is stateful, and
they widen both the ICV coverage and the AEAD associated data.

The structure limits what a new row can do. Adding an integrity algorithm
that is not an HMAC needs more than a row --
:class:`~pcapkit.protocols.internet.esp.IntegritySuite` records the digest as
the name of a :mod:`hashlib` constructor, which AES-XCBC and AES-CMAC are not.
And :func:`~pcapkit.protocols.internet.esp.load_cryptography` imports only the
``ciphers`` submodules of |cryptography|_, so the AEAD and CMAC primitives
have to be added there before a cipher suite can reach them. Unsupported
algorithms are refused loudly, when the Security Association is constructed
rather than when a packet is read, so nothing decodes wrongly in the meantime.

Mobility Header
~~~~~~~~~~~~~~~

**Done.**
:class:`~pcapkit.protocols.internet.mh.MH` decodes and constructs the whole
registry: **every registered message data type**, **every CGA extension**, and
**every registered option**. Every one of them is registered in
:attr:`~pcapkit.protocols.internet.mh.MH.__message__`,
:attr:`~pcapkit.protocols.internet.mh.MH.__option__` or
:attr:`~pcapkit.protocols.internet.mh.MH.__extension__` with both a ``_read_``
and a ``_make_`` handler.

Every message type and every one of those options round-trips byte-for-byte
through the public API -- ``make`` then ``read`` then ``make`` again reproduces
the same octets, which
:file:`tests/protocols/test_option_roundtrip_unit.py` checks for the whole
registry. The **CGA extensions round-trip end to end as well**: the CGA
Parameters option (type 12) is the only thing that can carry a CGA extension on
the wire, so registering it reached the whole
:attr:`~pcapkit.protocols.internet.mh.MH.__extension__` registry with it, and no
``mh-extension`` entry appears in that test's ``EXPECTED_FAILURES``.

The sub-registries are the easy half: binding revocation types and triggers,
handoff indicators, access network identifier sub-options, flow identification
and flow binding sub-options, LMA-controlled MAG parameters, DNS update status,
traffic selector formats and QoS attributes are all generated in full under
:doc:`/pcapkit/const/mh`. Value sets that IANA does not register live in ``mh.py`` itself rather than
in :mod:`pcapkit.const.mh`: the localized routing acknowledgment status codes of
:rfc:`6705#section-10.2`
(:class:`~pcapkit.protocols.internet.mh.LocalizedRoutingStatus`) and the local
mobility anchor address option codes of :rfc:`5949#section-6.2.2`
(:class:`~pcapkit.protocols.internet.mh.LMAAddressCode`). Sets from :rfc:`5568`
live there alongside them.

What is left, and why:

* **Payloads that belong to another protocol** are carried opaquely. The
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
  for the traffic selectors, and on the multicast options the message-type octet
  each carries: ``protocol`` on option 54, ``igmp_type`` and ``mld_type`` on 56
  and 57, and ``code`` on 60. Not the ``M`` flag on option 54, which selects the
  routing mode rather than the record format [:rfc:`7028#section-5.1.2`].
  :class:`~pcapkit.protocols.misc.raw.Raw` is already what an unregistered dispatch falls back
  to everywhere else in the package, so this makes the mobility header consistent
  with the rest rather than inventing a convention; and once a dissector for one
  of these formats exists, registering it needs no change at the option site.

  None of those keys is checked against the values its RFC allows, on
  either side. :rfc:`7028` says ``protocol`` MUST be 143 or 131 for MLD, or
  ``0x12``, ``0x16`` or ``0x22`` for IGMP, yet
  :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mcast_sel` builds and
  :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mcast_sel` parses any octet
  without a warning, and the other keys behave the same. The registry is
  where an unknown key would first be noticed, so the check belongs there rather
  than in each maker separately.

  It wants a registry of its own rather than
  :meth:`~pcapkit.protocols.protocol.Protocol._decode_next_layer`, which is
  only ever called at a layer boundary and appends to the frame's protocol chain.
  An MLD address record inside a mobility option does not follow MH on the wire,
  so putting it in that chain would make ``layer=`` and ``protocol=`` limits
  behave wrongly. Changing the parsed shape from :obj:`bytes` to
  :class:`~pcapkit.protocols.misc.raw.Raw` also changes what existing captures dump to, so
  it is its own change.

Wire-format traps are worth knowing before touching this code, since each
looks like an ordinary field and is not:

* :rfc:`7411`'s multicast options measure their length field in **32-bit
  words**, and exclude the option-code and status octets as well as the type and
  length ones -- so the option occupies ``4 + length * 4`` octets, not
  ``length + 2``.
* :rfc:`5213#section-8.8`'s timestamp is **not** an :rfc:`1305` NTP timestamp,
  though the mobility header carries both. It counts from the UNIX epoch in a
  48/16 fixed-point split, where NTP counts from 1900 in a 32/32 one, so reading
  one as the other is wrong in the epoch and in both field widths. They have
  separate types for that reason:
  :class:`~pcapkit.protocols.data.internet.mh.PMIPv6Timestamp` and
  :class:`~pcapkit.protocols.data.internet.mh.NTPTimestamp`.

DTLS
~~~~

**Done** for the record layer and handshake message framing:
:class:`~pcapkit.protocols.application.tls.TLS` (SSLv3, :rfc:`6101`; TLS
1.0, :rfc:`2246`; TLS 1.1, :rfc:`4346`; TLS 1.2, :rfc:`5246`; TLS 1.3,
:rfc:`9846`) and :class:`~pcapkit.protocols.application.dtls.DTLS` (DTLS
1.0, :rfc:`4347`; DTLS 1.2, :rfc:`6347`; DTLS 1.3, :rfc:`9147`) share
:class:`~pcapkit.protocols.application.ssl.SSL` as their record-layer base --
content type, legacy version, length, and content-type dispatch -- with
DTLS's own divergence (the epoch/sequence-number pair in its record header,
and the fragment header each handshake message carries) staying in
:class:`~pcapkit.protocols.application.dtls.DTLS` alone. ``ClientHello`` and
``ServerHello`` decode down to their cipher suite(s), compression method(s)
and extension list, and ``EncryptedExtensions`` down to its extension list. An
extension body decodes where
:attr:`SSL.__extension__ <pcapkit.protocols.application.ssl.SSL.__extension__>`
registers a decoder for its type, and stays raw octets where none is
registered or the decoder rejects it (:issue:`2514`). Every other handshake
message is message-TYPE-level framing only. Decryption is a
separate question and is not needed to make the record structure legible, in
the same way :class:`ESP <pcapkit.protocols.internet.esp.ESP>` parses
without keys.

**Done** for SSLv2 too (draft-hickman-netscape-ssl-00, :issue:`2457`):
:class:`~pcapkit.protocols.application.sslv2.SSLv2` shares
:class:`~pcapkit.protocols.application.ssl.SSL` by name only, since its 2- or
3-octet record header carries no content type and no ``0x03xx`` version. No port
binds it: on TCP port 443, TLS offers it a segment whose first record TLS
rejects, and adopts the parse only when that record is a complete
``CLIENT-HELLO`` or ``SERVER-HELLO``, keeping anything else
:class:`~pcapkit.protocols.misc.raw.Raw`. A whole record after the first is a
further layer, the previous record's payload (:issue:`2567`), with the exceptions
:mod:`pcapkit.protocols.application.sslv2` lists. Among them, a record with a
``RECORD-LENGTH`` of ``0`` is :class:`~pcapkit.protocols.misc.raw.Raw` together
with everything after it, and :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
bounds how many are dissected. :ref:`protocol-family-ssl` gives how ``id()`` and
``alias`` tell the family's members apart.

**Done: reassembling a handshake message DTLS has fragmented across several
records** (:rfc:`6347#section-4.2.3`, :issue:`2440`), via
:class:`~pcapkit.foundation.reassembly.dtls.DTLS`, keyed on the UDP 4-tuple
and the epoch. ``Extractor(reassembly=True, dtls=True)`` opts in on the
default engine, which feeds it through
:func:`pcapkit.toolkit.pcap.dtls_reassembly`, and
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes each
reassembled message, of any length (:issue:`2496`). In the frame itself every
fragment's body stays that one fragment's raw octets -- see
:attr:`DTLSHandshake.is_fragmented <pcapkit.protocols.data.application.dtls.DTLSHandshake.is_fragmented>`.
An unfragmented message is unaffected either way.

NGAP over DTLS over SCTP (PPID 66,
:class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`),
asked for in `discussion #251
<https://github.com/JarryShaw/PyPCAPKit/discussions/251>`__, is **not**
decoded: :attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.SCTP.__proto__>`
maps PPID 66 to :class:`~pcapkit.protocols.application.ngap.NGAP` rather than
through :class:`~pcapkit.protocols.application.dtls.DTLS`, so those bytes
degrade to :class:`~pcapkit.protocols.misc.raw.Raw`. Rewiring that dispatch
needs a decision on what an undecrypted DTLS-wrapped NGAP PDU reports.

Registered, but Not Dissected
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A different shape of gap from the empty stubs, and easy to miss because nothing
announces it. The :doc:`/pcapkit/const/reg` enumerations are complete, but only a
small part of each is bound to a dissector; everything else resolves to
:class:`~pcapkit.protocols.misc.raw.Raw`, so the capture parses without
complaint and yields nothing useful.

* :class:`~pcapkit.const.reg.linktype.LinkType` --
  ``NULL``, ``ETHERNET``, ``LOOP``, ``LINUX_SLL``, ``IPV4``, ``IPV6`` and
  ``LINUX_SLL2``, declared identically
  in :class:`~pcapkit.protocols.misc.pcap.frame.Frame` and
  :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`, which also read ``RAW`` as
  ``IPV4`` or ``IPV6`` by its version nibble.
* :class:`~pcapkit.const.reg.transtype.TransType` -- the values in
  :attr:`Internet.__proto__
  <pcapkit.protocols.internet.internet.Internet.__proto__>`.
* :class:`~pcapkit.const.reg.ethertype.EtherType` -- the values in
  :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`: ARP,
  RARP, IPv4, IPv6, IPX and both VLAN tags.
* :class:`~pcapkit.const.reg.apptype.apptype.AppType` -- the ports bound in
  :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>` and
  :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>`, out of
  a registry carrying every IANA service name: TCP 20 to FTP-DATA, 21 to FTP and
  443 to TLS, ports 80 and 8080 to HTTP on both TCP and UDP, and UDP 1701 to
  L2TPv2 and 5684 to DTLS.
* :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
  -- the values in :attr:`SCTP.__proto__
  <pcapkit.protocols.transport.sctp.SCTP.__proto__>`: PPIDs 60 and 66, each to
  :class:`~pcapkit.protocols.application.ngap.NGAP`. Every other DATA chunk
  payload is :class:`~pcapkit.protocols.misc.raw.Raw` until something calls
  :func:`~pcapkit.foundation.registry.protocols.register_sctp`.

How much of each registry is bound is measurable, so measure it rather than
trust a figure written down here:

.. code-block:: shell

   python -c "from pcapkit.protocols.internet.internet import Internet; \
              from pcapkit.const.reg.transtype import TransType; \
              print(len(Internet.__proto__), len(list(TransType)))"

Most of those want a dissector written and are covered by the stub list above.
Some wanted only a table entry, because the dissector was already there:

* **Done.** :class:`~pcapkit.protocols.application.ospf.OSPF` is bound at
  :class:`~pcapkit.const.reg.transtype.TransType` 89 (``OSPFIGP``) and
  :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` at UDP port 1701.
  ``__index__`` raises on both, which is correct: neither is reached through a
  link-layer EtherType.
* **Done.** :class:`~pcapkit.protocols.application.ftp_data.FTP_DATA` is bound at TCP
  port 20 (IANA ``ftp-data``). It is a thin
  :class:`~pcapkit.protocols.misc.raw.Raw` subclass, so this buys the payload a
  *name* rather than a parse -- which is the right answer for a data channel
  carrying an arbitrary file.
* **Done.** HTTP is additionally bound on 8080 (IANA ``http-alt``, "HTTP
  Alternate (see port 80)") on both TCP and UDP. TCP 443 (IANA ``https``) is
  bound to :class:`~pcapkit.protocols.application.tls.TLS` and UDP 5684 (IANA
  ``coaps``) to :class:`~pcapkit.protocols.application.dtls.DTLS`. **8443 is deliberately left unbound**: IANA registers it as
  ``pcsync-https``, not as an HTTP alternate, and binding it to HTTP would
  feed a TLS record to an HTTP parser; binding it to TLS instead would be a
  guess this registry does not make for a service IANA does not actually
  name there.
* **Done.** The service VLAN tag identifier (S-Tag), ``0x88A8``, is bound to
  :class:`~pcapkit.protocols.link.s_tag.S_Tag`, and the customer tag ``0x8100``
  to :class:`~pcapkit.protocols.link.c_tag.C_Tag`. Both subclass the abstract
  :class:`~pcapkit.protocols.link.vlan.VLAN`, which carries the shared tag
  layout; the split exists so that a Q-in-Q frame's two tags stay distinct in
  the parsed output.
* **Done.** :class:`~pcapkit.const.reg.linktype.LinkType` ``NULL`` and ``LOOP`` are bound to
  :class:`~pcapkit.protocols.link.loopback.Loopback`, which reads the four-octet
  address family word and hands 2 to IPv4 and 24, 28 or 30 to IPv6
  (:issue:`1574`). ``RAW`` has no binding of its own: its bare IPv4 or IPv6 is
  dispatched by the version nibble of the first octet (:issue:`1502`).

Follow-ups to the bindings above:

* :class:`~pcapkit.const.reg.transtype.TransType` 115 (``L2TP``) stays unbound, and the
  reason is structural: it references :rfc:`3931`, i.e. L2TPv3 over IP, and **there is
  no** ``L2TPv3`` **class for it to point at**. What exists is
  :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`, the :rfc:`2661` v2 framing, reached over
  UDP 1701. So the binding waits on a v3 dissector, which is also the first member of the
  family to carry an :meth:`~pcapkit.protocols.protocol.Protocol.__index__` of its own --
  115 being that index. :mod:`pcapkit.protocols.link.l2tp` records what v3 needs, and what
  ``L2F`` needs alongside it: the version nibble reading ``1`` selects L2F [:rfc:`2341`],
  a separate protocol, not an earlier L2TP.
* The :class:`~pcapkit.protocols.link.l2tp.L2TP` family lives under
  :mod:`pcapkit.protocols.link` and so reports ``layer == 'Link'``, although it
  is carried inside UDP. That is deliberate: a tunnelling protocol is placed by what
  it carries (:ref:`protocol-layer-placement`). It is inert for layer-limited
  extraction, since IPv4 and IPv6 terminate an ``internet`` extraction before it
  is reached.
* **Done.** :attr:`TCP.__proto__
  <pcapkit.protocols.transport.tcp.TCP.__proto__>` and :attr:`UDP.__proto__
  <pcapkit.protocols.transport.udp.UDP.__proto__>` both point their HTTP ports at
  the version-identifying proxy :class:`pcapkit.protocols.application.http.HTTP`
  rather than at :class:`pcapkit.protocols.application.httpv1.HTTPv1`, so a
  segment's HTTP version is decided by its payload rather than asserted by its
  port number. That depends on the proxy identifying the version positively
  instead of guessing, since a guess path is wrong on non-HTTP input.

**Done.** ICMP (1), ICMPv6 (58) and IGMP (2) -- the internet layer gaps most
likely to be met in a real capture -- are all implemented; ECN and Shim6
above are the open ones.

PCAPNG Support
--------------

**Done.** The builtin default engine parses PCAP-NG files;
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implements the format, with its
block and option enumerations under :doc:`/pcapkit/const/pcapng`. This closes
:issue:`35`.

Maybe Even Faster?
------------------

**Partly done.** A measured benchmark exists, and acting on it cut extraction
time on a 1117-frame HTTP capture by about 46% with byte-identical output. The
profiling found these wrong on the hot path, none of them the ones the thread
predicted:

* character-set detection was uncached, and accounted for 30% of an HTTP
  extraction -- 3011 :func:`chardet.detect` calls over 163 distinct
  bytestrings;
* every field of every protocol was copied through the generic
  :func:`copy.copy` machinery, 63207 times per extraction;
* :attr:`Field.length <pcapkit.corekit.fields.field.FieldBase.length>` recomputes
  :func:`struct.calcsize` on each read and was read two to four times per field;
* :class:`~pcapkit.protocols.schema.schema.Schema`'s ``__setattr__`` re-entered
  itself once per field assigned.

Predictions the profiling **contradicted**, recorded so nobody spends time on
them again: :class:`~pcapkit.corekit.infoclass.Info` construction -- the usual
suspect -- is 0.0% of its own cost and 4.4% of a parse, and the logging
integration is 0.03% even in the heaviest shape, since every call site is a lazy
``%s``. The IO-batching idea the thread proposed was never the bottleneck.

The larger costs this section listed all lie outside the parse path, and each is
addressed in full or in part:

* **The flow dumper reopens its output file once per frame**, in
  :class:`~pcapkit.dumpkit.pcap.PCAPIO`'s ``__call__``. It does not
  *also* rebuild a whole
  :class:`~pcapkit.protocols.misc.pcap.frame.Frame` to obtain bytes it already
  holds; dropping that re-dissection was about 82% of the cost of a flow-traced
  extraction by itself. The reopen is what remains.
* **A datagram is submitted for every frame, fragmented or not**, because
  :func:`~pcapkit.toolkit.pcap.ipv4_reassembly` filters only on the *DF* flag --
  so a capture with no fragments at all still produces one
  "datagram" per frame. Parsing its payload is not part of that cost:
  :attr:`Datagram.packet
  <pcapkit.foundation.reassembly.data.ip.Datagram.packet>` is a
  :class:`~pcapkit.foundation.reassembly.data.data.Deferred` parsed on first
  read, rather than running
  :meth:`~pcapkit.protocols.protocol.Protocol.analyze` eagerly on each one,
  measured at 86% of the IP-reassembly cost plus a 133 ms garbage-collection
  bill. Whether unfragmented frames should be emitted at all is the design
  question that is left, and it is worth settling deliberately.
* **Done.** :class:`~pcapkit.corekit.fields.collections.OptionField` reads only
  the base schema's type field to choose the option schema, rather than unpacking
  the whole base schema and throwing it away. Unpacking it parsed every option
  twice -- 2274 schema unpacks for 1137 options, the pre-parse always discarded,
  about 15% of a PCAP-NG extraction.

Some traps for anyone benchmarking this library. ``reassembly=True`` and
``trace=True`` are **no-ops** without ``ip=``/``tcp=``, so a benchmark that passes
only the switch measures nothing; and timing several capture shapes in one
process inflates them by up to 73%, so each shape wants its own interpreter.

Recursive Dissection, With a Depth Limit
----------------------------------------

**Decided, open to revisit.** Each layer dissects the next from inside
its own parse, so dissecting a frame recurses once per layer, at 9 to 12 Python
frames a layer. Without a bound, deep nesting -- IP in IP, stacked 802.1Q tags,
long chains of IPv6 extension headers -- exhausts the recursion limit and leaves the
rest of the frame raw, silently, at a depth that varies with the interpreter and
the caller's stack (:issue:`1604`, :issue:`1610`).

Recursion stays, with a counted bound:
:data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` caps a frame at 64 layers by
default, and :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` caps one
chain of extension headers at 32 by default. Past either, the rest stays
:class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning`. Raising
:func:`sys.setrecursionlimit` instead was rejected: it is process-wide, and the
cut-off would still move with the caller's stack. The bound fits with room to
spare, but not unlimited room. Under :program:`pytest` at the default limit of
1,000, the costliest 64-layer frame needs a limit of 834 on Python 3.11 and 756
on 3.14. That frame is IPv4 carrying a chain of 32 extension headers, then IPv4
in IPv4 carrying 28 more, then TCP.

An iterative model would need no such bound: a loop that dissects one layer and
takes the next from it. It changes how every protocol hands over its payload,
so it is a design of its own, and may replace the recursion in a future release.

Logging Integration
-------------------

**Done.** :mod:`pcapkit.utilities.logging` provides:

- a **logger hierarchy** rooted at ``pcapkit``, with every module logging
  through its own child obtained from
  :func:`~pcapkit.utilities.logging.get_logger`, so that a subtree such as
  ``pcapkit.foundation.registry`` can be silenced independently of
  ``pcapkit.foundation.extraction``;
- **library-safe defaults** -- importing :mod:`pcapkit` attaches only a
  :class:`logging.NullHandler` and sets no level, leaving the destination and
  verbosity to the application. :envvar:`PCAPKIT_DEVMODE` bootstraps a
  :obj:`sys.stderr` handler at :data:`logging.DEBUG`;
- a **runtime configuration API** --
  :func:`~pcapkit.utilities.logging.configure`,
  :func:`~pcapkit.utilities.logging.reset` and
  :func:`~pcapkit.utilities.logging.ensure_output` -- rather than a single
  environment variable read once at import;
- **levels chosen deliberately**. Registration bookkeeping across
  :mod:`pcapkit.foundation.registry` logs at ``debug`` rather than ``info``,
  since a library announcing its own registry entries is not news to its
  consumer;
- **debug coverage of the extraction path** -- extractor construction,
  engine selection and fallback, frame counts, cleanup, reassembly and
  flow-tracing setup -- so that ``DEBUG`` explains what PyPCAPKit did with a
  file without descending into per-field parsing.

See :doc:`/pcapkit/utilities/logging` for the configuration recipes, including
the one-line restore of :obj:`sys.stderr` output.

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
``pyproject.toml`` extra (``PyPCAPFile`` and ``PyPCAP``, neither of which
``all`` includes -- ``all`` carries core addons only, and ``PyPCAP`` also has
the installability problem below), docs
under :doc:`/pcapkit/foundation/engines/index`, and tests under
``tests/foundation/engines/`` and ``tests/toolkit/``. Like every third-party
engine, both are best effort: they need not match the ``default`` engine, and
protocol rules belong in the ``default`` engine only (:issue:`1687`).

Neither library, though, is usable straight from PyPI on a current Python, and
both of the following are worth knowing before reaching for them:

* **pypcapfile** -- the released 0.12.0 imports the ``imp`` module, removed in
  Python 3.12. Precisely, ``pcapfile/linklayer.py`` imports it at module scope
  and ``pcapfile.savefile`` imports ``linklayer``, so while a bare
  ``import pcapfile`` still succeeds on 3.12+, the modules the engine
  actually needs raise :exc:`ModuleNotFoundError`. Upstream ``master`` (0.12.1,
  unreleased) has fixed this, and that is what the engine was verified against.
  The extra therefore installs a version that does not work on Python 3.12 or
  newer until 0.12.1 is published.
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
  the libpcap development files from every user, and would break the docs
  build, which installs ``.[all,dev]`` on the macOS runner, where :file:`pcap.h`
  is present but no ``libpcap.dylib`` is.

  That is solved, though not by changing the ``PyPCAP`` extra. `pcap-ct
  <https://pypi.org/project/pcap-ct/>`__ re-implements the ``pypcap`` API in pure
  Python over :mod:`ctypes`, and it is wired up as a **separate engine**,
  :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`, selected with
  ``engine='pcap_ct'`` and installed with ``pip install pypcapkit[PCAP_CT]``. It
  works on every supported interpreter, verified on 3.10 and 3.14.

  A separate engine rather than a second backend because the two are **mutually
  exclusive**: both distributions own the import name |pcap|_, and with both
  installed ``pcap-ct`` wins the import while upstream's extension module is
  shadowed and unreachable. Each engine detects which backend it actually got and
  says so, rather than one ``engine=`` string silently meaning two different
  implementations.

  Caveats remain. Both distributions are still beta releases, and ``pcap-ct``
  targets the ``pypcap`` 1.2.3 API -- within what this engine uses, but worth
  knowing. And despite the `libpcap <https://pypi.org/project/libpcap/>`__ wheel
  bundling prebuilt binaries, a runtime ``libpcap`` shared library is still
  required: that wheel's published configuration sets ``LIBPCAP = None``, which
  sends the loader to ``find_library("pcap")``. No compiler and no
  :file:`pcap.h` are needed; a ``libpcap.so.1`` is.

Both engines support less than the ``default`` engine does, deliberately:
`pypcap`_ performs no protocol dissection, so it disables reassembly *and* flow
tracing; `pypcapfile`_ has no IPv6 decoder, so it disables IPv6 reassembly while
keeping IPv4 and TCP, and it disables DTLS reassembly, which reads :mod:`pcapkit`'s
own DTLS layer. Each gap is announced through an
:class:`~pcapkit.utilities.warnings.AttributeWarning` or an outright exception
rather than by silently returning nothing, save that `pypcapfile`_ leaves TCP
behind a VLAN tag, in a tunnel or behind an extension header (an IPv6 one, or AH
in IPv4) out of TCP reassembly and flow tracing without a warning --
:doc:`/pcapkit/foundation/engines/index` tabulates them.

Adding a further engine does not mean adding handler methods to
:class:`~pcapkit.foundation.extraction.Extractor`, as the thread describes. A new engine subclasses
:class:`pcapkit.foundation.engines.engine.Engine` and implements just
:meth:`~pcapkit.foundation.engines.engine.EngineBase.run`
and :meth:`~pcapkit.foundation.engines.engine.EngineBase.read_frame`; passing the
``engine`` class keyword registers it. See :doc:`/ext` for a worked example. What does
still apply is the unified auxiliary tools in :mod:`pcapkit.toolkit`, where
each engine has a matching module.

Test Cases
----------

**Largely done.** There is a systematic test suite under ``tests/``, and it runs
in CI against Python 3.11 through 3.15, per
``.github/workflows/unit-tests.yml``, and against the end-of-life 3.8 through 3.10
on legs whose failures block nothing.
The module count is measurable rather than worth writing down:

.. code-block:: shell

   find tests -name 'test_*.py' | wc -l

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

The original ask also included **shipping the suite**, and the answer is a
deliberate decision rather than an omission. ``tests`` is excluded from the wheel
by ``[tool.setuptools.packages.find]`` in ``pyproject.toml``; the sdist does carry
every module, so a distribution packager building from source has them. The
wheel stays lean because the suite could not run from an installed package
anyway: the generated sample captures are not shipped, and ``tests/_tiers.py``
resolves paths from a repository root that an installed package does not have.
Anyone wanting to run the tests wants the repository, which is where they are.

.. note::

   ``dictdumper``'s ``PLIST`` writer formats every :class:`~datetime.datetime` as
   ``'%Y-%m-%dT%H:%M:%S.%fZ'``, always with six fractional digits, and
   :mod:`plistlib`'s ``<date>`` pattern admits none, so without the workaround
   below :func:`plistlib.load` fails on every ``format='plist'`` report with
   ``AttributeError: 'NoneType' object has no attribute 'groupdict'``. The upstream defect is
   `JarryShaw/DictDumper#122 <https://github.com/JarryShaw/DictDumper/issues/122>`__.
   :func:`pcapkit.dumpkit.common.make_dumper` works around it (:issue:`1448`): it
   writes each date in UTC to whole seconds, as :func:`plistlib.dump` does. The
   exact value stays in the sibling field every timestamp already has, such as
   ``time_epoch``.
   ``PlistRoundTripTests.test_plist_report_round_trips_through_plistlib``, in
   ``tests/integration/test_output_formats.py``, checks the round trip.

Reassembly Beyond IP and TCP
----------------------------

**Still open.**
:doc:`/pcapkit/foundation/reassembly/index` covers IPv4, IPv6, TCP and DTLS
handshake messages (see `DTLS`_ above), and no more.
IPv4 and IPv6 share the :rfc:`791` procedure, and TCP uses the :rfc:`815`
hole-descriptor algorithm, which does handle out-of-order and overlapping
segments. SCTP has nothing: a user message split across DATA chunks is never put
back together, and :mod:`pcapkit.foundation.reassembly` has no SCTP reassembler.

What that costs is concrete. The dissector already exposes everything a
reassembler needs, on
:class:`~pcapkit.protocols.data.transport.sctp.DATAChunk` -- ``tsn``,
``stream_id``, ``stream_seq``, ``ppid``, ``data``, and ``flags.B`` and
``flags.E`` for the beginning and ending fragment bits -- and nothing reads
those two bits outside the construction path. So each fragment is dispatched on
its own PPID as though it were a whole PDU, and a registered upper layer is
handed half a message. Related holes compound it: only the *first* DATA
chunk of a bundle is dispatched at all, and I-DATA [:rfc:`8260`], chunk type 64,
is not dissected -- so the MID and FSN fields that exist precisely to make
interleaved reassembly tractable are never parsed, and an I-DATA-only packet
yields no payload whatsoever. FORWARD TSN (192) and I-FORWARD-TSN (194) are
likewise unhandled, so partial-reliability stream advancement is invisible.

Writing the reassembler is the smaller half of the job. It would go at
``pcapkit/foundation/reassembly/sctp.py``, subclass
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` and implement
:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly` and
:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.submit`. Registering
it, though, is inert:
:meth:`~pcapkit.foundation.extraction.Extractor.register_reassembly` accepts any
protocol name, while
:class:`~pcapkit.foundation.extraction.Extractor` only ever instantiates the
ones it names literally, and
:class:`~pcapkit.foundation.reassembly.ReassemblyManager` is a fixed-field
container with no room for another. Making SCTP reachable therefore also means
touching that manager and its read-side twin, the construction branch in
:class:`~pcapkit.foundation.extraction.Extractor`, one adapter per engine in
:mod:`pcapkit.toolkit`, the call site in each of those engines, and
:func:`~pcapkit.interface.core.reassemble`. Generalising that wiring so a
registered reassembler is actually used is worth doing on its own account, and
would make each further protocol cheaper than the last rather than dearer.

Smaller items in the same subsystem:

* **Flow tracing is TCP only**, and blocked on the same generalisation --
  :class:`~pcapkit.foundation.traceflow.TraceFlowManager` holds a single field,
  so UDP, SCTP and IP conversation tracing have nowhere to go.

  It does treat both directions of a connection as one flow, though.
  :meth:`TCP.make_bufid
  <pcapkit.foundation.traceflow.tcp.TCP.make_bufid>` orders the two endpoints
  canonically, so both halves of a conversation reduce to one buffer ID, one
  label and one output file, and
  :class:`~pcapkit.foundation.traceflow.data.tcp.Index` reports ``forward`` and
  ``reverse`` alongside ``index`` so per-direction ordering stays recoverable.
  This is the default; ``bidirectional=False``
  (``trace_bidirectional=False`` on
  :class:`~pcapkit.foundation.extraction.Extractor`,
  :func:`~pcapkit.interface.core.extract` and
  :func:`~pcapkit.interface.misc.follow_tcp_stream`) selects per-direction
  flows instead.

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
  <pcapkit.foundation.traceflow.traceflow.TraceFlow.finish>`. Distinguishing
  that SYN from the peer's SYN-ACK is what the recorded teardown is for.

  One case remains undecided rather than solved: a capture that *starts* in the
  middle of a connection, sees no teardown, and then has its endpoints reused. The
  reuse is indistinguishable from a continuation without the ACK flag on
  :class:`~pcapkit.foundation.traceflow.data.tcp.Packet`, which would make
  ``syn and not ack`` a definitive new-connection test on its own.

  **The application layer is wired into flow tracing** as well. Of the ways
  of buffering a traced payload, the tracer **delegates to**
  :class:`~pcapkit.foundation.reassembly.tcp.TCP` rather than growing a
  per-direction payload buffer of its own. A buffer that concatenated payloads in
  capture order would be silently wrong on the first retransmission or reordered
  segment, where the :rfc:`815` hole-descriptor algorithm already in the
  reassembler is not -- so
  :class:`~pcapkit.foundation.traceflow.data.tcp.Packet` carries the segment
  fields (``seq``, ``ack``, ``header``, ``payload``) that reassembler needs, and
  the tracer hands each traced segment straight to it.

  :attr:`Index.packet <pcapkit.foundation.traceflow.data.tcp.Index.packet>` then
  holds the reassembled datagrams, one per direction and acknowledgement number
  (:class:`~pcapkit.foundation.traceflow.tcp.TCP` says why), and postpones twice:
  reading it is what flushes the flow's reassembler, and each datagram's own
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
  <pcapkit.foundation.reassembly.reassembly.Reassembly.expire>` abandons a
  buffer whose first-arriving fragment is older than
  :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.timeout`
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

  On the numbers: the 15 seconds :rfc:`791` names is that RFC's *initial* timer
  setting, a lower bound which
  ``TIMER <- MAX(TIMER,TTL)`` then raises toward the 4.25-minute TTL ceiling --
  not a deadline. :rfc:`1122#section-3.3.2` supersedes the scheme outright
  ("The reassembly timeout value SHOULD be a fixed value, not set from the
  remaining TTL... between 60 seconds and 120 seconds"), so IPv4 uses 60
  seconds, agreeing with the 60 :rfc:`8200#section-4.5` mandates for IPv6.
  **TCP is left with no timeout at all**, since no specification gives stream
  reassembly a deadline and an idle connection is ordinary rather than
  pathological; ``timeout`` enables one on request.

  Related things are *not* done. :rfc:`8200#section-4.5` and
  :rfc:`1122#section-3.3.2` both want an ICMP Time Exceeded sent on expiry when
  the offset-zero fragment has been received; a parser sends nothing, so the
  condition is only reported in the log record. And the memory motive is
  narrowed rather than removed -- an in-flight IP datagram identifier still
  holds a fixed 72 KiB of preallocated space, but for at most the timeout's
  worth of capture time rather than for the life of the
  :class:`~pcapkit.foundation.extraction.Extractor`.

Reassembly is also unavailable on some engines rather than merely slower, which
is worth knowing before benchmarking against them: ``pyshark``, ``pypcap`` and
``pcap_ct`` disable it entirely, ``pypcapfile`` disables IPv6 and DTLS
reassembly, and the ``dpkt`` and ``scapy`` engines disable DTLS reassembly.
:doc:`/pcapkit/foundation/engines/index` tabulates that.

Checksum and Integrity Verification
-----------------------------------

These protocols parse a checksum or CRC field —
:class:`~pcapkit.protocols.link.gre.GRE`,
:class:`~pcapkit.protocols.internet.hip.HIP`,
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT`,
:class:`~pcapkit.protocols.internet.igmp.IGMP`,
:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`,
:class:`~pcapkit.protocols.internet.ipx.IPX`,
:class:`~pcapkit.protocols.internet.mh.MH`,
:class:`~pcapkit.protocols.application.ospf.OSPF`,
:class:`~pcapkit.protocols.transport.dccp.DCCP`,
:class:`~pcapkit.protocols.transport.sctp.SCTP`,
:class:`~pcapkit.protocols.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.udp.UDP` — and SCTP was the first to
check whether the value is *right*, through
:attr:`SCTP.checksum_valid <pcapkit.protocols.transport.sctp.SCTP.checksum_valid>`.
IPv4, OSPF, TCP, UDP and DCCP check it too, as do ICMP and ICMPv6, as the
one's-complement half below describes. For GRE, HIP, HOPOPT, IGMP, IPv6-Opts, IPX
and MH the field is recorded and never questioned, so a corrupted capture parses
as cleanly as an intact one; verifying GRE's and IGMP's is :issue:`2618`.

**These are different problems and they want separating**, because only one
of them is cryptographic and the distinction decides what is actually hard.

**The one's-complement Internet checksum**, which covers IPv4's header, TCP, UDP,
DCCP, ICMP/ICMPv6 and OSPF, needs no cryptography at all — it is sixteen-bit addition
with end-around carry, and implementing it is an afternoon. What blocks it is the
**IP pseudo-header**: the TCP, UDP, DCCP and ICMPv6 checksums are computed over source
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

**The cryptographic integrity checks** are where the |cryptography|_
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

The policy questions this raised have all been settled by the repo
owner, and each lands on a precedent the library already has:

* **Verification is opt-in.** Checksumming every packet costs real time on a
  large capture, and `Maybe Even Faster?`_ above is a standing concern, so it is
  a flag rather than unconditional behaviour.
* **A wrong checksum is a warning, not a hard failure, and the outcome is
  recorded on the protocol class.** The warning is a
  :class:`~pcapkit.utilities.warnings.ChecksumWarning`, a
  :class:`~pcapkit.utilities.warnings.ProtocolWarning` of its own so a filter can
  silence it alone (:issue:`2470`), and the recording has an
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

One case was left to implementation time, since it is about wording rather
than design: **checksum offload**. A capture taken on the sending
host routinely contains checksums the NIC had not computed yet, so the field is
zero or garbage on the wire and "invalid" is the wrong word for it. Whatever
status enumeration this grows should be able to say *not computed* distinctly
from *wrong*, or it will cry wolf on the commonest capture there is —
:class:`~pcapkit.protocols.internet.esp.ESPStatus`'s ``NO_SA`` member is the
model for how to spell "expected, not an error".

**The one's-complement half is done** (:issue:`2470`, :issue:`2472` to
:issue:`2475`), on :class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo`
(:issue:`2471`) and :mod:`pcapkit.corekit.checksum.internet`, settled as
below: the toggles by the owner on :issue:`2471`, the rest at implementation,
as the offload question above asked; the owner accepted the toggles and the
offload heuristic on :issue:`2470`.

* **Every checksum path is togglable, and verifying and computing default apart.** Parsing
  verifies only under :envvar:`PCAPKIT_CHECKSUM_VERIFY`, off by default;
  construction computes a checksum the caller leaves out unless
  :envvar:`PCAPKIT_CHECKSUM_COMPUTE` turns it off.
* **The toggle is an environment variable**, with a per-call override only where
  a caller needs one. A checksum given to ``make()`` is written as given, which is
  what keeps a rebuild byte for byte; there is no
  :class:`~pcapkit.foundation.extraction.Extractor` or per-instance parameter.
* **The IP layer owns the pseudo-header.** :class:`~pcapkit.protocols.internet.ipv4.IPv4`
  and :class:`~pcapkit.protocols.internet.ipv6.IPv6` verify their upper layer's
  checksum once parsed, and compute it for an upper layer constructed as their
  payload; ``make()`` of TCP, UDP and ICMPv6 also takes the ``pseudo`` itself.
* **Offload is** :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NOT_COMPUTED`,
  modelled on ``NO_SA``: a zero IPv4 or TCP checksum, or a TCP or UDP one holding
  the pseudo-header's sum alone, as Linux offload leaves it, never warns. So does
  a zero UDP checksum over IPv4 (:rfc:`768`), but not over IPv6, where it is
  mandatory (:rfc:`8200#section-8.1`).
* **A fragment is**
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NO_PSEUDO_HEADER`,
  atomic ones aside: TCP, UDP, ICMP and ICMPv6 checksums cover all of the
  datagram's data, which it carries part of. OSPF's Packet Length says what its
  checksum covers, so it is verified when the fragment holds that much, and
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.TRUNCATED`
  otherwise.
* **DCCP covers what its Checksum Coverage gives** (:rfc:`4340#section-9.2`), over
  a pseudo-header that carries the whole packet's length, as TCP's does, so a
  fragment is
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NO_PSEUDO_HEADER`
  too. A coverage running past the packet, which the RFC forbids and has the
  receiver ignore, is
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.INVALID` and
  warns. Linux, until it dropped DCCP in 6.16, never sent one: its
  ``dccp_csum_outgoing`` wrote a CsCov of 0 wherever the coverage reached the
  end of the packet, and ``make()`` does the same when it computes the
  checksum. No value is
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NOT_COMPUTED`:
  DCCP has no checksum to leave out, and Linux computed it in software rather
  than offloading it. Settled at implementation (:issue:`2489`).

The cryptographic half is sequenced for **wave 3**, and could be done sooner
since ESP has already laid the groundwork.

Deterministic Construction Arguments
------------------------------------

This is meant to open a broader run of proposals for the construction
(``make()``) workflow in general rather than stand alone -- more will be added
under that heading as they get scoped, and the concrete item ready to write
down now is making a ``make()`` call's own argument list deterministic.

:meth:`~pcapkit.protocols.protocol.Protocol._make_index` is where that is not
currently true. A number of ``make()`` methods accept a plain ``str``
enum-member name for a field and resolve it by frame-introspecting the
caller's locals for a conventional four-argument group -- ``X``,
``X_default``, ``X_namespace`` and ``X_reversed`` -- looking for the one
argument whose own default is an enum member, and taking that member's class
as the namespace to search. The actual contract of a ``make()`` call is
therefore not fully visible from its own signature: knowing what a bare
string resolves against means knowing the convention and trusting that every
call site followed it exactly, rather than reading it off the call itself.
That gap is exactly how this round's bug family happened. :issue:`2356` is
the walk coming up empty because the relevant argument's own default is
``None``, leaving nothing to anchor a namespace to; :issue:`2394` is the same
inference failing by a different route -- the name is a loop variable over a
*list* parameter rather than a scalar argument, so the walk's
``isinstance(value, str)`` check can never see it. Both were fixed narrowly,
by naming the correct enum explicitly at each affected call site rather than
touching the inference, so the mechanism is exactly as fragile as it was
before and just as liable to the same shape of defect at the next call site
that does not fit its assumptions precisely.

The owner's proposed direction -- recorded here, and explicitly **not**
scheduled for 1.5.0 -- removes the inference rather than patching it again.
``make()`` would require an actual enum value, or an ``int`` where one is
already accepted, for these fields, with no implicit string-to-enum
resolution performed inside ``make()`` itself. In its place, a small public
wrapper would take the same four-argument group explicitly -- name, default,
namespace, reversed -- and *resolve* a string name to its enum member on
request, so a caller holding a bare string calls that helper first and passes
the resolved value into ``make()``. That mirrors how a finalised
:class:`~pcapkit.corekit.infoclass.Info` or
:class:`~pcapkit.protocols.schema.schema.Schema` already settles its
constructor's keyword set once, when
:func:`~pcapkit.corekit.infoclass.info_final` or
:func:`~pcapkit.protocols.schema.schema.schema_final` is applied at
class-definition time, rather than inferring it afresh at every call --
:attr:`~pcapkit.protocols.protocol.Protocol.__own_make_keywords__`
(:issue:`2286`) settles the same kind of question explicitly rather than
inferring it, though for a different question: which keywords a ``make()``
override owns, not what the names passed to it resolve against.

The trade-off is real and worth stating rather than glossed over. Accepting a
bare string for these fields is a pattern used throughout the docs and the
examples, so dropping the inference is a likely-breaking change at every
``make()`` call site that currently relies on it -- not a one-line fix.
Deciding that scope -- which call sites change, whether string acceptance is
dropped outright or only the silent-inference path behind it, and what the
wrapper is named and where it lives -- is itself design work, which is
exactly why this belongs on this page rather than as a quick issue. Done, it
removes the root cause of the :issue:`2356`/:issue:`2394` family rather than
leaving its next instance to be found and patched the same way.

**Scoped for 1.6.0.** The owner took this direction for every ``make()``, ruled
in review of :pr:`2593` (:issue:`2489`): a field holding an enum takes the member
or an ``int``, resolved with the enumeration's ``get`` rather than inferred from
the caller's frame. The shipped ``X_default``, ``X_namespace`` and ``X_reversed``
keywords go in 1.6.0 with no deprecation period, ruled on :issue:`2594`, which
carries the change across :file:`pcapkit/protocols/` in one pass and leaves the
helper's name and module to it.

Release Plan — 1.5.0 in Two Steps
---------------------------------

:data:`pcapkit.__version__` is the current version, and the release is sequenced
against the waves above in two deliberate steps:

#. **A beta —** ``1.5.0b1`` **— when wave 1's remaining issues are closed.**
   *Done.* Wave 1's feature work had landed already; what remained was the
   defect tail in `the issue tracker
   <https://github.com/JarryShaw/PyPCAPKit/issues>`__, and closing it earned a
   beta rather than a final release, because the consistency sweep below had not
   run yet and was expected to find things.
#. **The official** ``1.5.0`` **when the post-wave-1 consistency sweep is done.**
   *Done.* The sweep is described under `Delivery Sequence`_ below — prose
   against code, missing tests, unaligned changes, packet formats against the
   specifications, and duplicated logic. Its whole point was to find what
   one-at-a-time defect work does not, and its verified findings are closed:
   :issue:`490`, :issue:`491`, :issue:`492`, :issue:`493`, :issue:`494`,
   :issue:`495` and :issue:`496`, alongside the prose strand's own
   :issue:`719`. A later defect wave made the prose strand's ground move again,
   so it ran a second time as :issue:`1103`; that is closed too. ``1.5.0``
   shipped once this work was in.

**The version string is the release button, so it is worth knowing exactly what
each step does before editing it.** ``.github/workflows/create-release.yml`` is
version-driven rather than tag-driven: its ``version_check`` job reads
:data:`pcapkit.__version__` directly, derives ``PCAPKIT_PRERELEASE`` from
``packaging.version.Version(...).is_prerelease``, and picks the Anaconda label
from the same test.

Worth spelling out how that workflow is *reached*, because reading its ``on:``
block alone suggests it is not reachable from an ordinary commit at all — it
lists only ``push`` on ``v*`` tags and a ``workflow_run``. The chain has an
extra hop: a push to ``main`` triggers **Unit Tests**
(``unit-tests.yml``), whose completion triggers **Vendor Update**
(``cron-vendor.yml``) via ``workflow_run`` -- ``cron-vendor.yml`` carries no
``push`` trigger of its own, deliberately, per the comment on its
``workflow_run`` trigger -- and *that* completion triggers **Create Release**
itself. :doc:`workflows` draws the chain among the repository's other workflows.

Every publishing job — ``github``, ``tag``, ``pypi``, ``conda`` — is gated on
``startsWith(github.ref_name, 'v')`` or on evidence that its own target still
needs publishing. Only ``github`` gates on ``PCAPKIT_TAG_EXISTS``, because the
tag that output answers for is the one ``github`` is about to create. ``tag``,
``pypi`` and ``conda`` each gate on their own target instead -- whether the
matching Conda tag exists, whether PyPI's file count for the version has
reached the expected total, whether Anaconda's upload is complete. Each of
those additionally requires ``version_check`` and the release test gate
(``unit-tests``) to have succeeded, and ``github`` -- and, for ``conda``,
``tag`` -- to have succeeded *or skipped*. ``github`` itself needs the gate
directly, and the gate runs only when one of the publishing jobs would.
Those conditions open with ``!cancelled()``, which suppresses the ``success()``
Actions would otherwise prepend; accepting ``skipped`` is then what stops an
upstream job's legitimate skip cascading into skipping a job whose own evidence
says it still has work to do. Naming the two states rather than writing "not
failed" is deliberate: a *cancelled* dependency then skips the job below it
cleanly, instead of letting it run against an artefact that was never
produced.

That is why an ordinary commit does not publish: the version string has not
moved, so each job's own check finds its target already there and every one of
them skips, as does the full-suite release test gate ahead of them. Changing the
version string is what flips every one of those checks, and the next push then
tags and publishes. So:

.. list-table::
   :header-rows: 1
   :widths: 20 20 20 40

   * - version
     - prerelease
     - conda label
     - GitHub release
   * - ``1.5.0aN`` / ``1.5.0bN`` (step 1)
     - yes
     - ``dev``
     - marked prerelease
   * - ``1.5.0`` (step 2)
     - **no**
     - ``main``
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

**Wave 1 — done.** The Mobility Header registry completion, the protocol
bindings (FTP-DATA, HTTP-alt, OSPF, L2TP, the 802.1ad S-Tag), the
:class:`~pcapkit.protocols.link.vlan.VLAN` C-Tag/S-Tag split, the option
round-trip coverage harness, and reassembly's :rfc:`8200` timeout with
bidirectional flow tracing. Its defect tail closed out through the
post-wave-1 consistency sweep described under `Release Plan — 1.5.0 in Two
Steps`_ above.

**Wave 2 — the protocol pairs that want a shared abstract base, done** (ruled on
:issue:`2564`), per `More Protocols, More!!!`_ above: **TLS/SSL with DTLS** and
**IGMP** and **DCCP** on their own. These are grouped because the shared-base
question is the design work and doing either half of a pair alone would answer it
twice.

**DCCP — done within wave 2** (:issue:`2489`).
:class:`~pcapkit.protocols.transport.dccp.DCCP` dissects every :rfc:`4340` packet
type and DCCP-Listen (:rfc:`5596`), with short and long sequence numbers, and the
options :rfc:`4340` defines; its checksum is verified and computed over
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo`, as `Checksum and
Integrity Verification`_ above describes. The Data Checksum option's CRC-32c is
recorded and not checked.

**Done within wave 2 — ICMP/ICMPv6 shared base.** :class:`~pcapkit.protocols.internet.icmp.ICMP`
is the abstract base :class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` and
:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6` share for selector composition
(:issue:`2436`); each implements its own message-type parsing independently rather than
through a shared method body. The two are distinguished by whether they carry pseudo-header
checksums (ICMPv6 does; ICMPv4 does not), both verified and computed (:issue:`2470`).

**IGMP — done within wave 2** (:issue:`2439`, :issue:`2448`).
The three concrete classes :class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.IGMPv1>`,
:class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.IGMPv2>` and
:class:`IGMPv3 <pcapkit.protocols.internet.igmpv3.IGMPv3>` share one read path on
the abstract :class:`~pcapkit.protocols.internet.igmp.IGMP` base, which
:meth:`~pcapkit.protocols.internet.igmp.IGMP._classify` dispatches to the right
one. IGMPv1/v2 share one 8-octet message shape; IGMPv3 (:rfc:`3376`) adds the
Membership Query's source-list extension and the Membership Report's
group-record list, each a shape of its own.

**Done within wave 2 — TLS/SSL with DTLS.** The `DTLS`_ section above lists
what is decoded: the shared :class:`~pcapkit.protocols.application.ssl.SSL`
base, SSLv2 (:issue:`2457`, :issue:`2567`), TLS, DTLS, handshake message
framing, the hello and
``EncryptedExtensions`` extension lists with their registered extension bodies
(:issue:`2514`), and handshake-fragment reassembly (:issue:`2440`).

**Done ahead of wave 2 — handlers for the** ``DLT_NULL``, ``DLT_RAW``,
``DLT_LINUX_SLL`` **and** ``DLT_LINUX_SLL2`` **link types.** Each is a
genuine DLT that a capture can legitimately be rooted in — ``DLT_NULL`` (0)
is BSD's loopback encapsulation, ``DLT_RAW`` (101) an IP packet with no link
header at all, and ``DLT_LINUX_SLL`` (113) with ``DLT_LINUX_SLL2`` (276) the
Linux "cooked" capture header every ``tcpdump -i any`` capture uses.
:class:`~pcapkit.protocols.link.loopback.Loopback` dissects ``DLT_NULL`` and
``DLT_LOOP`` (:issue:`1574`), the frame dispatcher reads ``DLT_RAW`` as IPv4
or IPv6 by its version nibble (:issue:`1502`), and
:class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1` with
:class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2` dissect the Linux
cooked-capture variants (:issue:`2438`). The ``arphrd_type`` values
neither header treats as carrying an EtherType each have a dissector of their own
(:issue:`2460`), dispatched through :attr:`LinuxSLL.__proto__
<pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>` (:issue:`2510`):
``NETLINK`` to :class:`~pcapkit.protocols.link.netlink.Netlink`, ``IPGRE`` and
``IP6GRE`` to :class:`~pcapkit.protocols.link.gre.GRE`, ``FRAD`` to
:class:`~pcapkit.protocols.link.frad.FRAD`, and ``IEEE80211_RADIOTAP`` to
:class:`~pcapkit.protocols.link.radiotap.Radiotap` (:issue:`2502`), which keeps its
optional fields undissected (:issue:`2576`) and hands the 802.11 frame to
:class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11`, which dissects the MAC
header and keeps the frame body :class:`~pcapkit.protocols.misc.raw.Raw`
(:issue:`2575`).
Neither ``NULL`` nor ``RAW`` is an honest stand-in for "unknown
link type", which is why the toolkit raises for an unresolvable link-layer
name instead of defaulting to :attr:`LinkType.NULL
<pcapkit.const.reg.linktype.LinkType.NULL>`.

**Wave 3 — the remaining protocols** from the same list, taken three or four at a
time. QUIC, DSL, FDDI and ISDN come last: QUIC because it is really HTTP/3 over a
new transport and wants that settled first, the rest because a capture in
the wild is rare enough that the work buys little until the commoner protocols
are in.

**Sequenced after wave 2 — the Mobility Header sub-layer registry.** Several
mobility options carry a payload belonging to another protocol, and those
payloads want carrying as :class:`~pcapkit.protocols.misc.raw.Raw` through a
per-payload registry rather than as bare :obj:`bytes` — see `Mobility Header`_
above, which describes the payloads in question and why a registry of their own
is wanted instead of
:meth:`~pcapkit.protocols.protocol.Protocol._decode_next_layer`. It is
sequenced *after* wave 2 rather than by preference: the multicast options embed
:rfc:`9777` MLD (which obsoletes :rfc:`3810`; :rfc:`2710` for MLDv1), which
rides in **ICMPv6**, and :rfc:`3376` **IGMPv3** group records. ICMPv6 and
IGMP, IGMPv3 included (:issue:`2448`), are both wave 2 deliverables, done;
MLD itself is a follow-up to ICMPv6 (see `More Protocols, More!!!`_
above). Landing the registry first would give a dispatch table with
:class:`~pcapkit.protocols.misc.raw.Raw` to register. The
counter-argument is real though, and worth weighing rather than dismissing: changing the
parsed shape from :obj:`bytes` to :class:`~pcapkit.protocols.misc.raw.Raw` is the
disruptive half, since it changes what existing captures dump to, so there is a case for
taking that churn early and registering dissectors later. The remaining format, the
:rfc:`6088` traffic selectors of :rfc:`6089` and :rfc:`7222`, has no wave at all — it is a
registry of its own and nobody has claimed it.

**Wave 3 — per-entry coverage of the option and parameter registries.** The
option, parameter, block and frame registries are *enumerated* but not
*implemented* throughout: a code can be registered, and named, and still have no
working per-entry read/make pair behind it. The goal of this item is to close
that gap to zero for every code whose format is actually specified.

Both halves of the gap are measurable — the registered codes against the
families :file:`examples/generators/options.py` walks, and the shortfall
against ``EXPECTED_FAILURES`` in
:file:`tests/protocols/test_option_roundtrip_unit.py` — so the commands are
written down instead of figures that will be stale by the next merge:

.. code-block:: shell

   # registered codes, and the families they are drawn from
   python -c "import sys; sys.path.insert(0, 'examples/generators'); import options; \
              print(len(options.cases()), len(options.FAMILIES))"

   # codes that do not round-trip, grouped by family
   python -c "import collections, importlib.util, sys; \
              spec = importlib.util.spec_from_file_location('rt', \
                  'tests/protocols/test_option_roundtrip_unit.py'); \
              m = importlib.util.module_from_spec(spec); sys.modules['rt'] = m; \
              spec.loader.exec_module(m); \
              print(collections.Counter(k.split('/')[0] for k in m.EXPECTED_FAILURES))"

Things to be precise about before anyone starts. First, the round-trip half
is closed: ``EXPECTED_FAILURES`` is empty, so every case the harness enumerates
round-trips, and a new entry there would record a defect rather than a
deferral. Second, **round-tripping is not the same as being implemented** — the
harness walks the codes each protocol registers a handler for, not every code
its enumeration names, so what remains is the codes with no per-entry handler,
such as the SCTP chunk types under `SCTP`_ above, which fall through to the
generic handlers and parse as opaque.

This is deliberately **not** the same request as the ``__proto__`` dispatch
registries. Those name whole protocols, so closing a gap there means
implementing a dissector — bounded by protocol work that already has its own
waves above. The option and parameter registries are per-entry formats inside
protocols that already exist, so the work is self-contained and does not wait on
anything. Their enumerating harness already exists and already fails when a
registered code has no case, which is how the shortfall is known at all; what is
missing is the implementations behind the codes, not the accounting of them.
:file:`tests/protocols/test_dispatch_registry_unit.py` gives the ``__proto__``
family the same accounting for the separate question of whether a registered
protocol's dispatch reaches it.

**Between wave 1 and wave 2 — a library-wide consistency sweep, done**, its
findings listed under `Release Plan — 1.5.0 in Two Steps`_ above. Clearing
defects one at a time, each found because something else was being worked on
nearby, is a poor way to find the rest of them. So the sweep is deliberate, and
divided into strands:

* **Prose against code.** Docstrings, the README, and inline comments checked
  against what the code does. A docstring outliving the thing it described is a
  demonstrated failure mode here rather than a hypothetical one. Includes the
  rule that a docstring names the real defining module rather than the
  re-export.
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
  :issue:`472` — HIP
  parameters sizing their list entries at one octet where :rfc:`5770` §5.4 and
  :rfc:`7402` §5.1.2 specify sixteen bits — and the same method then *cleared*
  the further
  ``EnumField(length=1)`` sites in the same file against :rfc:`7401`,
  :rfc:`8002`, :rfc:`8003`, :rfc:`5770` and :rfc:`6078`. It both finds real
  defects and retires suspicion, which is why it is worth doing exhaustively
  rather than opportunistically.
* **Duplicated logic that wants a shared module.** The same method or the same
  arithmetic written out in several protocols, where one definition would do.
  This strand has the sharpest evidence of them all, because duplication here has
  already *caused* defects rather than merely offended tidiness:

  - :issue:`487` existed because
    :meth:`IPv6_Route.make() <pcapkit.protocols.internet.ipv6_route.IPv6_Route.make>`
    computed ``Hdr Ext Len`` in **separate** branches with different wrong units, and the
    read side computed the inverse elsewhere with yet another. The fix was not new
    arithmetic but one helper per direction, each documenting the :rfc:`8200#section-4.4`
    unit and saying what its counterpart is.
  - :issue:`483` was the scapy
    toolkit adapter passing a fragment offset unscaled where every sibling
    adapter scaled it. Every adapter restates the same field mapping, so a
    convention that holds in all but one is invisible until a capture is
    wrong.

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

**Queued for wave 3 — cryptographic integrity verification.** See `Checksum
and Integrity Verification`_ above. HIP's ``HIP_MAC``/``RVS_HMAC``/``RELAY_HMAC``
and its signature parameters could start whenever, since
:class:`~pcapkit.protocols.internet.esp.ESP` has already established both the
keying-context channel and the report-rather-than-raise policy. The
one's-complement half (IPv4, TCP, UDP, ICMP/ICMPv6, OSPF) is **done**
(:issue:`2470`, :issue:`2472` to :issue:`2475`), and DCCP's with it (:issue:`2489`).

**IP pseudo-header — done** (:issue:`2471`).
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo` is the
**pseudo-protocol class** for the IP family the owner settled on, serving both
the parsing and the constructing path, rather than a back-reference from a
parsed protocol to its parent.

**Scoped for 1.6.0 — deterministic construction arguments** (:issue:`2594`). See
`Deterministic Construction Arguments`_ above: every ``make()`` takes an enum
field as the member or an ``int``, dropping the implicit string-to-enum inference
and the ``X_default``, ``X_namespace`` and ``X_reversed`` keywords behind it, and
an explicit helper resolves a bare string. That breaks every call site relying on
the inference, so it lands as one change rather than folded into the next defect
fix on this family.
