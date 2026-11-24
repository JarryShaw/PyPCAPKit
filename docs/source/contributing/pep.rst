Help Wanted
===========

.. important::

   This page is the maintained copy of the project's enhancement proposals, kept
   in step with the code. The `discussion thread
   <https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ holds them as first
   raised; here an implemented proposal is described as implemented, and only open
   work is asked for. Leave notes in the thread rather than against this page.

Pull requests for anything still open, and new ideas of your own, are very
welcome. For questions, leave a note in the `discussion thread
<https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ or under the `Q&A
category <https://github.com/JarryShaw/PyPCAPKit/discussions/categories/q-a>`__.

.. note::

   This page tracks **feature requests**, not defects. A defect that work on an
   item turns up goes in `the issue tracker
   <https://github.com/JarryShaw/PyPCAPKit/issues>`__ and is linked from here. A
   design question that needs a decision before anyone can implement it is a
   request, and belongs here.

Wish you enjoy **PyPCAPKit**!!!

More Protocols, More!!!
-----------------------

Every protocol not decoded is wanted. Adding one is self-contained: a package
holding a protocol, a schema and a data class (:ref:`protocol-family-grouping`),
as sketched in
`discussion #251 <https://github.com/JarryShaw/PyPCAPKit/discussions/251>`__,
whose reply is the closest thing to a step-by-step guide. Outstanding, by TCP/IP
layer and alphabetically, each with its issue:

* Link Layer: EAPOL (:issue:`2974`), FDDI (:issue:`3005`), LLC/SNAP
  (:issue:`2936`)
* Internet Layer: Neighbor Discovery, in ICMPv6 (:issue:`2934`); Shim6
  (:issue:`3014`), which
  :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext` frames without
  decoding its message bodies
* Transport Layer: QUIC (:issue:`3001`)
* Application Layer: BGP (:issue:`2981`), DHCP (:issue:`2959`), DHCPv6
  (:issue:`2973`), IMAP (:issue:`2972`), LDAP (:issue:`2988`), MQTT
  (:issue:`2977`), NNTP (:issue:`2980`), NTP (:issue:`2968`), ONC/RPC
  (:issue:`2992`), POP (:issue:`2964`), RIP (:issue:`2982`), RSVP
  (:issue:`2985`), RTP (:issue:`2995`), SIP (:issue:`2998`), SMTP
  (:issue:`2960`), SNMP (:issue:`2979`), SSH (:issue:`2967`), Telnet
  (:issue:`3004`), XMPP (:issue:`3020`)

QUIC and RSVP sit where :issue:`2805` placed them: QUIC in transport, and RSVP in
application beside OSPF.

**Done**: :class:`~pcapkit.protocols.link.ppp.protocol.PPP` and
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` (:issue:`2817`),
:class:`~pcapkit.protocols.application.dns.protocol.DNS` (:issue:`2816`), and
MLDv1 and MLDv2 in :class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`
(:issue:`2812`).

Neighbor Discovery (:issue:`2934`) is still open. Its messages (:rfc:`4861`),
ICMPv6 types 133 to 137, belong to ICMPv6 rather than to a protocol of their own;
like any type
:attr:`ICMPv6.__type__ <pcapkit.protocols.internet.icmpv6.protocol.ICMPv6.__type__>`
does not register, each is read today down to its type, code and checksum, with
its body kept raw.

ECN is decoded where its bits are a field of their own: IPv4's as ``tos.ecn``, a
:class:`~pcapkit.const.ipv4.tos_ecn.ToSECN`, beside its precedence and
type-of-service bits, and TCP's as the ``ns``, ``cwr`` and ``ece`` flags. IPv6
keeps its Traffic Class as one integer, ``class``; splitting it into DSCP and ECN
is :issue:`3000`.

Several protocols came in pairs that wanted a shared abstract base rather than two
independent implementations, in the way
:class:`~pcapkit.protocols.internet.ip.protocol.IP` and
:class:`~pcapkit.protocols.internet.ipsec.protocol.IPsec` cover their families.
**Done**:
:class:`~pcapkit.protocols.internet.icmp.protocol.ICMP` is the base of ICMPv4 and
ICMPv6, :class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL` that of the two
Linux cooked-capture headers, and
:class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`,
:class:`~pcapkit.protocols.application.tls.protocol.TLS` and
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS` share
:class:`~pcapkit.protocols.application.ssl.protocol.SSL` as their base by name, and only
TLS and DTLS share its record layer -- see the `DTLS`_ section
below. :class:`~pcapkit.protocols.link.vlan.protocol.VLAN` is the closer precedent
for a pair whose *layout* is identical -- it holds the whole of the tag, and
:class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag` and
:class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag` add only how each names itself.

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

**Done.** :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` is a first-class
transport layer protocol implemented per :rfc:`9260`: the common header, every
chunk type, chunk parameter and error cause the RFC defines, and CRC32c checksum
verification. It also reads and builds the I-DATA and I-FORWARD-TSN chunks
(:rfc:`8260`), the FORWARD TSN chunk and Forward-TSN-Supported parameter
(:rfc:`3758`), the PAD chunk and Padding parameter (:rfc:`4820`), and the
Supported Extensions parameter (:rfc:`5061`) (:issue:`2811`).

Unlike its siblings, it dispatches the next layer on the *payload protocol
identifier* of the first DATA or I-DATA chunk through
:func:`~pcapkit.foundation.registry.protocols.transport.register_sctp`, not on port
numbers, so :func:`~pcapkit.foundation.registry.protocols.transport.register_apptype`
deliberately does not fan out to it.

Still wanted are the registered-but-unimplemented type codes. IANA registers
more chunk types, chunk parameters and error causes than these
(:doc:`/pcapkit/const/sctp` lists them), and the surplus falls through to the
generic handlers: a capture using one parses, but yields an opaque chunk
instead of its fields. AUTH, ASCONF, ASCONF-ACK, RE-CONFIG and the DTLS chunk,
with their parameters and error causes, and the Zero Checksum Acceptable
parameter, are :issue:`2989`.

SCTP also wants its user messages reassembled (:issue:`2935`) and every DATA or
I-DATA chunk of a bundle dispatched, not only the first (:issue:`2993`) -- see
`Reassembly Beyond IP and TCP`_ below.

ESP
~~~

**Done.** :class:`~pcapkit.protocols.internet.esp.protocol.ESP` parses without keys, and
decrypts when a Security Association is supplied through the protocol keyed
:mod:`pcapkit.corekit.context` channel.

Still wanted is wider algorithm coverage. The enumerations
under :doc:`/pcapkit/const/esp` --
:class:`~pcapkit.const.esp.cipher.Cipher` and
:class:`~pcapkit.const.esp.integrity.Integrity` -- carry every transform IANA has
registered, but :data:`~pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.protocol.INTEGRITY_SUITES` apply only a few of
them, the no-ops ``ENCR_NULL`` and ``NONE`` among them. So the real coverage is
AES-CBC and AES-GCM at every tag length for encryption, and HMAC-SHA1-96 plus
the :rfc:`4868` HMAC-SHA2 truncations for integrity.

Not implemented, roughly in the order a capture is likely to want them:
AES-CTR [:rfc:`3686`], AES-CCM at every tag length [:rfc:`4309`],
ChaCha20-Poly1305 [:rfc:`7634`], AES-XCBC-MAC-96 [:rfc:`3566`], AES-CMAC-96
[:rfc:`4494`], the AES-GMAC family and its ``ENCR_NULL_AUTH_AES_GMAC``
counterpart [:rfc:`4543`] and the Camellia family, all :issue:`2958`; then the
implicit-IV [:rfc:`8750`] family, with Extended Sequence Numbers
(:issue:`2963`), and the MGM [:rfc:`9227`] family (:issue:`3009`). Extended
Sequence Numbers are the one item on this list that is not simply a table entry:
the high-order 32 bits are never transmitted, so recovering them is stateful,
and they widen both the ICV coverage and the AEAD associated data.

The structure limits what a new row can do. Adding an integrity algorithm
that is not an HMAC needs more than a row --
:class:`~pcapkit.protocols.internet.esp.protocol.IntegritySuite` records the digest as
the name of a :mod:`hashlib` constructor, which AES-XCBC and AES-CMAC are not.
And :func:`~pcapkit.protocols.internet.esp.protocol.load_cryptography` imports only the
``ciphers`` submodules of |cryptography|_, so the AEAD and CMAC primitives
have to be added there before a cipher suite can reach them. Unsupported
algorithms are refused loudly, when the Security Association is constructed
rather than when a packet is read, so nothing decodes wrongly in the meantime.

Mobility Header
~~~~~~~~~~~~~~~

**Done.**
:class:`~pcapkit.protocols.internet.mh.protocol.MH` decodes and constructs the whole
registry: **every registered message data type**, **every CGA extension**, and
**every registered option**. Every one of them is registered in
:attr:`~pcapkit.protocols.internet.mh.protocol.MH.__message__`,
:attr:`~pcapkit.protocols.internet.mh.protocol.MH.__option__` or
:attr:`~pcapkit.protocols.internet.mh.protocol.MH.__extension__` with both a ``_read_``
and a ``_make_`` handler.

Every message type and every one of those options round-trips byte-for-byte
through the public API -- ``make`` then ``read`` then ``make`` again reproduces
the same octets, which
:file:`tests/protocols/test_option_roundtrip_unit.py` checks for the whole
registry. The **CGA extensions round-trip end to end as well**: the CGA
Parameters option (type 12) is the only thing that can carry a CGA extension on
the wire, so registering it reached the whole
:attr:`~pcapkit.protocols.internet.mh.protocol.MH.__extension__` registry with it, and no
``mh-extension`` entry appears in that test's ``EXPECTED_FAILURES``.

The sub-registries are the easy half: binding revocation types and triggers,
handoff indicators, access network identifier sub-options, flow identification
and flow binding sub-options, LMA-controlled MAG parameters, DNS update status,
traffic selector formats and QoS attributes are all generated in full under
:doc:`/pcapkit/const/mh`. Value sets that IANA does not register live in
:mod:`pcapkit.protocols.internet.mh.protocol` rather than in :mod:`pcapkit.const.mh`:
the localized routing acknowledgment status codes of
:rfc:`6705#section-10.2`
(:class:`~pcapkit.protocols.internet.mh.protocol.LocalizedRoutingStatus`) and the local
mobility anchor address option codes of :rfc:`5949#section-6.2.2`
(:class:`~pcapkit.protocols.internet.mh.protocol.LMAAddressCode`). Sets from :rfc:`5568`
live there alongside them.

What is left, and why:

* **Payloads that belong to another protocol** are carried opaquely. The
  multicast options (54, 56, 57, 60 and 61) embed :rfc:`3810` MLD or :rfc:`3376`
  IGMP address records, and the traffic selectors of :rfc:`6089` and :rfc:`7222`
  embed the flag-driven range lists of :rfc:`6088`. Each is a separate registry
  with its own dissector's worth of structure; the mobility options around them
  are fully decoded, and each records which format its payload is in.

  What is wanted is to carry these as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
  rather than as bare :obj:`bytes`, dispatched through a **per-payload registry**
  in the style of :attr:`MH.__option__ <pcapkit.protocols.internet.mh.protocol.MH.__option__>`,
  keyed on the field that already names the format --
  :attr:`~pcapkit.protocols.internet.mh.schema.TrafficSelectorSuboption.ts_format`
  for the traffic selectors, and on the multicast options the message-type octet
  each carries: ``protocol`` on option 54, ``igmp_type`` and ``mld_type`` on 56
  and 57, and ``code`` on 60. Not the ``M`` flag on option 54, which selects the
  routing mode rather than the record format [:rfc:`7028#section-5.1.2`].
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw` is already what an unregistered dispatch falls back
  to everywhere else in the package, so this makes the mobility header consistent
  with the rest rather than inventing a convention; and once a dissector for one
  of these formats exists, registering it needs no change at the option site.
  The registry is :issue:`2937`; the dissectors it would register are
  :issue:`2994` for the MLD and IGMPv3 records and :issue:`2990` for the
  :rfc:`6088` traffic selectors.

  None of those keys is checked against the values its RFC allows, on
  either side. :rfc:`7028` says ``protocol`` MUST be 143 or 131 for MLD, or
  ``0x12``, ``0x16`` or ``0x22`` for IGMP, yet
  :meth:`~pcapkit.protocols.internet.mh.protocol.MH._make_opt_mcast_sel` builds and
  :meth:`~pcapkit.protocols.internet.mh.protocol.MH._read_opt_mcast_sel` parses any octet
  without a warning, and the other keys behave the same. The registry is
  where an unknown key would first be noticed, so the check belongs there rather
  than in each maker separately, and :issue:`2937` carries it.

  It wants a registry of its own rather than
  :meth:`~pcapkit.protocols.protocol.Protocol._decode_next_layer`, which is
  only ever called at a layer boundary and appends to the frame's protocol chain.
  An MLD address record inside a mobility option does not follow MH on the wire,
  so putting it in that chain would make ``layer=`` and ``protocol=`` limits
  behave wrongly. Changing the parsed shape from :obj:`bytes` to
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw` also changes what existing captures dump to, so
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
  :class:`~pcapkit.protocols.internet.mh.data.PMIPv6Timestamp` and
  :class:`~pcapkit.protocols.internet.mh.data.NTPTimestamp`.

DTLS
~~~~

**Done** for the record layer and handshake message framing:
:class:`~pcapkit.protocols.application.tls.protocol.TLS` (SSLv3, :rfc:`6101`; TLS
1.0, :rfc:`2246`; TLS 1.1, :rfc:`4346`; TLS 1.2, :rfc:`5246`; TLS 1.3,
:rfc:`9846`) and :class:`~pcapkit.protocols.application.dtls.protocol.DTLS` (DTLS
1.0, :rfc:`4347`; DTLS 1.2, :rfc:`6347`; DTLS 1.3, :rfc:`9147`) share
:class:`~pcapkit.protocols.application.ssl.protocol.SSL` as their record-layer base --
content type, legacy version, length, and content-type dispatch -- with
DTLS's own divergence (the epoch/sequence-number pair in its record header,
and the fragment header each handshake message carries) staying in
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS` alone. ``ClientHello`` and
``ServerHello`` decode down to their cipher suite(s), compression method(s)
and extension list, and ``EncryptedExtensions`` down to its extension list. An
extension body decodes where
:attr:`SSL.__extension__ <pcapkit.protocols.application.ssl.protocol.SSL.__extension__>`
registers a decoder for its type, as it does for the extensions a current hello
carries (:issue:`2810`), and only in the messages its RFC defines it in; it stays
raw octets elsewhere, where none is registered, or where the decoder rejects it
(:issue:`2514`). Decoding the other extensions IANA registers is :issue:`2966`.
Every other handshake message is message-TYPE-level framing only; decoding their
bodies, and heartbeat and ACK records, is :issue:`2969`. Decryption is a
separate question and is not needed to make the record structure legible, in
the same way :class:`ESP <pcapkit.protocols.internet.esp.protocol.ESP>` parses
without keys. **Still open:** a TLS record split across TCP segments is not
reassembled, and stays :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
(:issue:`2938`).

**Done** for SSLv2 too (draft-hickman-netscape-ssl-00, :issue:`2457`):
:class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2` shares
:class:`~pcapkit.protocols.application.ssl.protocol.SSL` by name only, since its 2- or
3-octet record header carries no content type and no ``0x03xx`` version. No port
binds it: on TCP port 443, TLS offers it a segment whose first record TLS
rejects, and adopts the parse only when that record is a complete
``CLIENT-HELLO`` or ``SERVER-HELLO``, keeping anything else
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`. A whole record after the first is a
further layer, the previous record's payload (:issue:`2567`), with the exceptions
:mod:`pcapkit.protocols.application.sslv2.protocol` lists. Among them, a record with a
``RECORD-LENGTH`` of ``0`` is :class:`~pcapkit.protocols.misc.raw.protocol.Raw` together
with everything after it, and :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
bounds how many are dissected. :ref:`protocol-family-ssl` gives how ``id()`` and
``alias`` tell the family's members apart.

**Done: reassembling a handshake message DTLS has fragmented across several
records** (:rfc:`6347#section-4.2.3`, :issue:`2440`), via
:class:`~pcapkit.foundation.reassembly.dtls.reassembly.DTLS`, keyed on the UDP
4-tuple and the epoch. ``reassembly=['dtls']`` opts in, on the default engine
alone, which feeds it through the ``dtls_reassembly`` adapters of
:mod:`pcapkit.toolkit.pcap` and :mod:`pcapkit.toolkit.pcapng`, and
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes each
reassembled message, of any length (:issue:`2496`). In the frame itself every
fragment's body stays that one fragment's raw octets -- see
:attr:`DTLSHandshake.is_fragmented <pcapkit.protocols.application.dtls.data.DTLSHandshake.is_fragmented>`.
An unfragmented message is unaffected either way.

NGAP over DTLS over SCTP (PPID 66,
:class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`),
asked for in `discussion #251
<https://github.com/JarryShaw/PyPCAPKit/discussions/251>`__, is **not**
decoded: :attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__>`
maps PPID 66 to :class:`~pcapkit.protocols.application.ngap.protocol.NGAP` rather than
through :class:`~pcapkit.protocols.application.dtls.protocol.DTLS`, so those bytes
degrade to :class:`~pcapkit.protocols.misc.raw.protocol.Raw`. Rewiring that dispatch
is :issue:`2971`, which needs a decision on what an undecrypted DTLS-wrapped NGAP
PDU reports.

Registered, but Not Dissected
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A gap easy to miss, because nothing announces it. The
:doc:`/pcapkit/const/reg` enumerations are complete, but only a small part of
each is bound to a dissector; everything else resolves to
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, so the capture parses without
complaint and yields nothing useful.

* :class:`~pcapkit.const.reg.linktype.LinkType` --
  ``NULL``, ``ETHERNET``, ``PPP``, ``PPP_HDLC``, ``PPP_ETHER``, ``IEEE802_11``,
  ``FRELAY``, ``LOOP``, ``LINUX_SLL``, ``IEEE802_11_RADIOTAP``, ``IPV4``, ``IPV6``
  and ``LINUX_SLL2``, declared identically
  in :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` and
  :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`, which also read ``RAW`` as
  ``IPV4`` or ``IPV6`` by its version nibble.
* :class:`~pcapkit.const.reg.transtype.TransType` -- the values in
  :attr:`Internet.__proto__
  <pcapkit.protocols.internet.internet.Internet.__proto__>`.
* :class:`~pcapkit.const.reg.ethertype.EtherType` -- the values in
  :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`: ARP,
  RARP, IPv4, IPv6, IPX, PPP, both PPPoE stages and both VLAN tags.
* :class:`~pcapkit.const.reg.apptype.apptype.AppType` -- the ports bound in
  :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>` and
  :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.protocol.UDP.__proto__>`, out of
  a registry carrying every IANA service name: TCP 20 to FTP-DATA, 21 to FTP and
  443 to TLS, ports 53 to DNS and 80 and 8080 to HTTP on both TCP and UDP, and UDP
  1701 to L2TPv2 and 5684 to DTLS. :attr:`DCCP.__proto__
  <pcapkit.protocols.transport.dccp.protocol.DCCP.__proto__>`, keyed by the same
  registry, binds no port, so every DCCP payload is
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw` until something calls
  :func:`~pcapkit.foundation.registry.protocols.transport.register_dccp`; binding
  its syslog-tls and avt-profile ports is :issue:`2999`.
* :class:`~pcapkit.const.linux.arphrd.ARPHRD` -- the values in :attr:`LinuxSLL.__proto__
  <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>` (:issue:`2510`), each an
  ``arphrd_type`` neither Linux cooked-capture header reads as an EtherType
  (:issue:`2460`): ``NETLINK``, ``IPGRE``, ``IP6GRE``, ``FRAD`` and
  ``IEEE80211_RADIOTAP``. Behind radiotap,
  :class:`~pcapkit.protocols.link.ieee802_11.protocol.IEEE802_11` dissects the MAC header
  and keeps the frame body :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
  (:issue:`2575`): a data frame's LLC/SNAP is :issue:`2936`, and management frame
  bodies are :issue:`2975`.
* :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
  -- the values in :attr:`SCTP.__proto__
  <pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__>`: PPIDs 60 and 66, each to
  :class:`~pcapkit.protocols.application.ngap.protocol.NGAP`. Every other DATA chunk
  payload is :class:`~pcapkit.protocols.misc.raw.protocol.Raw` until something calls
  :func:`~pcapkit.foundation.registry.protocols.transport.register_sctp`. The PPIDs
  a document formats are planned: the ones carried over DTLS (:issue:`2971`, and
  4242 in :issue:`2989`), the SIGTRAN adaptation layers (:issue:`3016`), Diameter
  (:issue:`3019`), WebRTC's data channels (:issue:`3015`), the 3GPP and O-RAN
  application protocols (:issue:`3012`, :issue:`3018`), ITU-T signalling
  (:issue:`3021`) and the other RFC-specified ones (:issue:`3010`).
  `Not Planned`_ lists the rest.

How much of each registry is bound is measurable:

.. code-block:: shell

   python -c "from pcapkit.protocols.internet.internet import Internet; \
              from pcapkit.const.reg.transtype import TransType; \
              print(len(Internet.__proto__), len(list(TransType)))"

Most of those want a dissector written, and are the protocols listed above.
Some wanted only a table entry, because the dissector was already there:

* **Done.** :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` is bound at
  :class:`~pcapkit.const.reg.transtype.TransType` 89 (``OSPFIGP``) and
  :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` at UDP port 1701, and
  ``__index__`` returns those values: ``TransType.OSPFIGP``, and 1701 as an
  :class:`int`, as an AppType-valued index is the member's port
  (:ref:`registry-protocol-index`).
* **Done.** :class:`~pcapkit.protocols.application.ftp_data.protocol.FTP_DATA` is bound at TCP
  port 20 (IANA ``ftp-data``). It is a thin
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw` subclass, so this buys the payload a
  *name* rather than a parse -- which is the right answer for a data channel
  carrying an arbitrary file.
* **Done.** HTTP is additionally bound on 8080 (IANA ``http-alt``, "HTTP
  Alternate (see port 80)") on both TCP and UDP. TCP 443 (IANA ``https``) is
  bound to :class:`~pcapkit.protocols.application.tls.protocol.TLS` and UDP 5684 (IANA
  ``coaps``) to :class:`~pcapkit.protocols.application.dtls.protocol.DTLS`. 8443
  is unbound: IANA registers it as ``pcsync-https``, not as an HTTP alternate, so
  binding it to HTTP would feed a TLS record to an HTTP parser. Binding TCP 8443
  to TLS, and leaving UDP 8443 unbound, is :issue:`3017`, as the owner ruled on
  :issue:`2805`.
* **Done.** The service VLAN tag identifier (S-Tag), ``0x88A8``, is bound to
  :class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag`, and the customer tag ``0x8100``
  to :class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag`. Both subclass the abstract
  :class:`~pcapkit.protocols.link.vlan.protocol.VLAN`, which carries the shared tag
  layout; the split exists so that a Q-in-Q frame's two tags stay distinct in
  the parsed output.
* **Done.** :class:`~pcapkit.const.reg.linktype.LinkType` ``NULL`` and ``LOOP`` are bound to
  :class:`~pcapkit.protocols.link.loopback.protocol.Loopback`, which reads the four-octet
  address family word and hands 2 to IPv4 and 24, 28 or 30 to IPv6
  (:issue:`1574`). ``RAW`` has no binding of its own: its bare IPv4 or IPv6 is
  dispatched by the version nibble of the first octet (:issue:`1502`). Neither
  ``NULL`` nor ``RAW`` stands in for an unknown link type: the toolkit raises for
  a link-layer name it cannot resolve rather than defaulting to :attr:`LinkType.NULL
  <pcapkit.const.reg.linktype.LinkType.NULL>`.

Follow-ups to the bindings above:

* :class:`~pcapkit.const.reg.transtype.TransType` 115 (``L2TP``) stays unbound, and the
  reason is structural: it references :rfc:`3931`, i.e. L2TPv3 over IP, and **there is
  no** ``L2TPv3`` **class for it to point at**. What exists is
  :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`, the :rfc:`2661` v2 framing, reached over
  UDP 1701, which is its :meth:`~pcapkit.protocols.protocol.Protocol.__index__`. So the
  binding waits on a v3 dissector, :issue:`2976`. :mod:`pcapkit.protocols.link.l2tp.protocol`
  records what v3 needs, and what ``L2F`` needs alongside it: the version nibble
  reading ``1`` selects L2F [:rfc:`2341`], a separate protocol, not an earlier
  L2TP, which is :issue:`3011`.
* The :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` family lives under
  :mod:`pcapkit.protocols.link` and so reports ``layer == 'Link'``, although it
  is carried inside UDP. That is deliberate: a tunnelling protocol is placed by what
  it carries (:ref:`protocol-layer-placement`). It is inert for layer-limited
  extraction, since IPv4 and IPv6 terminate an ``internet`` extraction before it
  is reached.
* **Done.** :attr:`TCP.__proto__
  <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>` and :attr:`UDP.__proto__
  <pcapkit.protocols.transport.udp.protocol.UDP.__proto__>` both point their HTTP ports at
  the version-identifying proxy :class:`pcapkit.protocols.application.http.protocol.HTTP`
  rather than at :class:`pcapkit.protocols.application.httpv1.protocol.HTTPv1`, so a
  segment's HTTP version is decided by its payload rather than asserted by its
  port number. That depends on the proxy identifying the version positively
  instead of guessing, since a guess path is wrong on non-HTTP input.

**Done.** ICMP (1), IGMP (2), DCCP (33), GRE (47) and ICMPv6 (58) -- the IP
protocol numbers most likely to be met in a real capture -- are all implemented
and bound.

PCAPNG Support
--------------

**Done.** The builtin default engine parses PCAP-NG files;
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` implements the format, with its
block and option enumerations under :doc:`/pcapkit/const/pcapng`. This closes
:issue:`35`. :class:`~pcapkit.dumpkit.pcapng.PCAPNGIO` writes the format, as the
``pcapng`` output of an extraction and of a flow tracer (:issue:`2835`).

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
* :class:`~pcapkit.protocols.schema.Schema`'s ``__setattr__`` re-entered
  itself once per field assigned.

Predictions the profiling **contradicted**, recorded so nobody spends time on
them again: :class:`~pcapkit.corekit.infoclass.Info` construction -- the usual
suspect -- is 0.0% of its own cost and 4.4% of a parse, and the logging
integration is 0.03% even in the heaviest shape, since every call site is a lazy
``%s``. The IO-batching idea the thread proposed was never the bottleneck.

The larger costs lie outside the parse path:

* **Done.** A flow tracer keeps each flow's output file open between its frames,
  up to :data:`~pcapkit.utilities.config.TRACE_OPEN_FILE_LIMIT` files, rather
  than reopening it for every frame in :class:`~pcapkit.dumpkit.pcap.PCAPIO`'s
  ``__call__`` (:issue:`2815`). Nor does the dumper rebuild a whole
  :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` to obtain bytes it
  already holds; dropping that re-dissection was about 82% of the cost of a
  flow-traced extraction by itself.
* **A datagram is submitted for every frame, fragmented or not**, because
  :func:`~pcapkit.toolkit.pcap.ipv4_reassembly` filters only on the *DF* flag --
  so a capture with no fragments at all still produces one
  "datagram" per frame. Parsing its payload is not part of that cost:
  :attr:`Datagram.packet
  <pcapkit.foundation.reassembly.ip.data.Datagram.packet>` is a
  :class:`~pcapkit.foundation.reassembly.data.Deferred` parsed on first
  read, rather than running
  :meth:`~pcapkit.protocols.protocol.Protocol.analyze` eagerly on each one,
  measured at 86% of the IP-reassembly cost plus a 133 ms garbage-collection
  bill. Whether unfragmented frames should be emitted at all is the design
  question that is left, and :issue:`2961` asks for that ruling.
* **Done.** :class:`~pcapkit.corekit.fields.collections.OptionField` reads only
  the base schema's type field to choose the option schema, rather than unpacking
  the whole base schema and throwing it away. Unpacking it parsed every option
  twice -- 2274 schema unpacks for 1137 options, the pre-parse always discarded,
  about 15% of a PCAP-NG extraction.

A trap for anyone benchmarking this library: timing several capture shapes in one
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
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning`. Raising
:func:`sys.setrecursionlimit` instead was rejected: it is process-wide, and the
cut-off would still move with the caller's stack. The bound fits with room to
spare, but not unlimited room. Under :program:`pytest` at the default limit of
1,000, the costliest 64-layer frame needs a limit of 834 on Python 3.11 and 756
on 3.14. That frame is IPv4 carrying a chain of 32 extension headers, then IPv4
in IPv4 carrying 28 more, then TCP.

An iterative model would need no such bound: a loop that dissects one layer and
takes the next from it. It changes how every protocol hands over its payload,
so it is a design of its own, and it ships alone in a major release, as ruled on
:issue:`2805`. Its issue is not filed yet.

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
:doc:`/pcapkit/foundation/engines/index` tabulates them, and `Not Planned`_ gives
each gap's issue.

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
The module count is measurable:

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
have no implementation yet. Pinning what each of them reaches today, so that a
test fails as one gains a handler, is :issue:`3008`.

The original ask also included **shipping the suite**. ``tests`` is excluded from
the wheel by ``[tool.setuptools.packages.find]`` in ``pyproject.toml``; the sdist
does carry every module, so a distribution packager building from source has
them. Nor could the suite run from an installed package: the generated sample
captures are not shipped, and ``tests/_tiers.py`` resolves paths from a
repository root that an installed package does not have. Shipping it in the
wheel, runnable from an install, is :issue:`3022`, as the owner ruled on
:issue:`2805`.

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
IPv4 and IPv6 share the :rfc:`791` procedure, except that a fragment overlapping
another abandons an IPv6 datagram, as :rfc:`8200#section-4.5` requires, where IPv4
overwrites the octets it overlaps (:issue:`2547`). TCP uses the :rfc:`815`
hole-descriptor algorithm, which does handle out-of-order and overlapping
segments. SCTP has nothing: a user message split across DATA or I-DATA chunks is
never put back together, and :mod:`pcapkit.foundation.reassembly` has no SCTP
reassembler (:issue:`2935`).

What that costs is concrete. The dissector already exposes everything a
reassembler needs, on
:class:`~pcapkit.protocols.transport.sctp.data.DATAChunk` -- ``tsn``,
``stream_id``, ``stream_seq``, ``ppid``, ``data``, and ``flags.B`` and
``flags.E`` for the beginning and ending fragment bits -- and on
:class:`~pcapkit.protocols.transport.sctp.data.IDATAChunk`, whose ``mid`` and
``fsn`` exist to make interleaved reassembly tractable (:issue:`2811`). The
dispatch reads none of the fragment fields: a packet's first DATA or I-DATA
chunk is dispatched on its PPID as though it were a whole PDU, so a registered
upper layer can be handed part of a message. Only that chunk of a bundle is
dispatched at all; dispatching every whole message is :issue:`2993`.

The reassembler would be a package at ``pcapkit/foundation/reassembly/sctp/``,
whose class subclasses
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` and implements
:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly` and
:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.submit`. The wiring
already takes it: a reassembler registered in :attr:`Extractor.__reassembly__
<pcapkit.foundation.extraction.Extractor.__reassembly__>` is enabled by name, made
by :meth:`~pcapkit.foundation.extraction.Extractor.make_reassembly`, held by
:class:`~pcapkit.foundation.reassembly.ReassemblyManager` and fed through each
engine's adapter in :attr:`EngineBase.__reassembly__
<pcapkit.foundation.engines.engine.EngineBase.__reassembly__>`, so a further
protocol costs one class plus one adapter per engine (:issue:`2814`).

Smaller items in the same subsystem:

* **Flow tracing is TCP only**, because TCP's is the only tracer
  :attr:`Extractor.__traceflow__
  <pcapkit.foundation.extraction.Extractor.__traceflow__>` registers. Any
  registered tracer named in ``traceflow`` is made and fed, through each engine's
  adapter in :attr:`EngineBase.__traceflow__
  <pcapkit.foundation.engines.engine.EngineBase.__traceflow__>`, and
  :class:`~pcapkit.foundation.traceflow.TraceFlowManager` holds the enabled
  tracers by name (:issue:`2843`). Tracers for UDP, SCTP and IP conversations are
  :issue:`2956`.

  It does treat both directions of a connection as one flow, though.
  :meth:`TCP.make_bufid
  <pcapkit.foundation.traceflow.tcp.traceflow.TCP.make_bufid>` orders the two
  endpoints canonically, so both halves of a conversation reduce to one buffer
  ID, one label and one output file, and
  :class:`~pcapkit.foundation.traceflow.tcp.data.Index` reports ``forward`` and
  ``reverse`` alongside ``index`` so per-direction ordering stays recoverable.
  This is the default; ``bidirectional=False``, on
  :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` or in the
  :class:`~pcapkit.foundation.options.TraceFlowOptions` that
  :class:`~pcapkit.foundation.extraction.Extractor`,
  :func:`~pcapkit.interface.core.extract` and
  :func:`~pcapkit.interface.misc.follow_tcp_stream` take as ``traceflow``,
  selects per-direction flows instead.

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
  reuse is indistinguishable from a continuation without the ACK flag, which
  :class:`~pcapkit.foundation.traceflow.tcp.data.Packet` does not carry as a
  field. Reading it, in a rule that also survives a simultaneous open
  (:rfc:`9293#section-3.5`) and a retransmitted SYN, is :issue:`2962`.

  **The application layer is wired into flow tracing** as well. Of the ways
  of buffering a traced payload, the tracer **delegates to**
  :class:`~pcapkit.foundation.reassembly.tcp.reassembly.TCP` rather than growing a
  per-direction payload buffer of its own. A buffer that concatenated payloads in
  capture order would be silently wrong on the first retransmission or reordered
  segment, where the :rfc:`815` hole-descriptor algorithm already in the
  reassembler is not -- so
  :class:`~pcapkit.foundation.traceflow.tcp.data.Packet` carries the segment
  fields (``seq``, ``ack``, ``header``, ``payload``) that reassembler needs, and
  the tracer hands each traced segment straight to it.

  :attr:`Index.packet <pcapkit.foundation.traceflow.tcp.data.Index.packet>` then
  holds the reassembled datagrams, one per direction and acknowledgement number
  (:class:`~pcapkit.foundation.traceflow.tcp.traceflow.TCP` says why), and
  postpones twice: reading it is what flushes the flow's reassembler, and each
  datagram's own
  :attr:`~pcapkit.foundation.reassembly.tcp.data.Datagram.packet` is parsed later
  still, through the same
  :class:`~pcapkit.foundation.reassembly.data.Deferred` arrangement the
  reassembly side uses. It is **opt-in** -- ``analyze=True``, on
  :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` or in
  :class:`~pcapkit.foundation.options.TraceFlowOptions` -- because buffering every
  traced payload is a cost tracing does not otherwise pay, and tracing's
  per-packet cost is something this package has deliberately driven down. It is
  unavailable on the ``pyshark`` engine, which reports dissected fields rather
  than the octets behind them, and which for the same reason has no reassembly
  adapter at all; asking for it there warns and falls back.
* **Timing a partial datagram out** is implemented.
  :meth:`Reassembly.expire
  <pcapkit.foundation.reassembly.reassembly.Reassembly.expire>` abandons a
  buffer whose first-arriving fragment is older than
  :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.timeout`
  seconds, and the buffer models carry the timestamp that makes it possible.

  The clock is the **capture's own timestamps**, not the host's: an offline
  parser has no other notion of time passing, and keying on
  :func:`time.time` would make the same file reassemble differently on every
  run. An extraction advances every enabled reassembler to each frame's
  timestamp through :meth:`Reassembly.advance
  <pcapkit.foundation.reassembly.reassembly.Reassembly.advance>` before feeding
  it the frame (:issue:`2814`), so a stalled buffer is reported as
  :attr:`~pcapkit.foundation.reassembly.data.Completion.TIMEOUT` once any later
  frame passes its deadline, whatever that frame's protocol. A reassembler fed by
  hand sees only the packets handed to it, so a buffer none follows is reported
  as :attr:`~pcapkit.foundation.reassembly.data.Completion.PARTIAL` at the end
  of the capture.

  On the numbers: the 15 seconds :rfc:`791` names is that RFC's *initial* timer
  setting, a lower bound which
  ``TIMER <- MAX(TIMER,TTL)`` then raises toward the 4.25-minute TTL ceiling --
  not a deadline. :rfc:`1122#section-3.3.2` supersedes the scheme outright
  ("The reassembly timeout value SHOULD be a fixed value, not set from the
  remaining TTL... between 60 seconds and 120 seconds"), so IPv4 uses 60
  seconds, agreeing with the 60 :rfc:`8200#section-4.5` mandates for IPv6.
  **TCP and DTLS are left with no timeout at all**, since no specification gives
  their reassembly a deadline, and an idle TCP connection is ordinary rather than
  pathological; ``timeout`` enables one on request.

  The memory motive is narrowed rather than removed: an in-flight IP datagram
  identifier still holds a fixed 72 KiB of preallocated space, but for at most
  the timeout's worth of capture time rather than for the life of the
  :class:`~pcapkit.foundation.extraction.Extractor`. Sizing each buffer to the
  fragments it holds is :issue:`2957`. :rfc:`8200#section-4.5` and
  :rfc:`1122#section-3.3.2` also want an ICMP Time Exceeded sent on expiry when
  the offset-zero fragment has been received; a parser sends nothing, so the
  condition is only reported in the log record.

Reassembly is also unavailable on some engines rather than merely slower, which
is worth knowing before benchmarking against them: ``pyshark``, ``pypcap`` and
``pcap_ct`` disable it entirely, ``pypcapfile`` disables IPv6 and DTLS
reassembly, and the ``dpkt`` and ``scapy`` engines disable DTLS reassembly.
:doc:`/pcapkit/foundation/engines/index` tabulates that.

Checksum and Integrity Verification
-----------------------------------

**Partly done.** The one's-complement checksums are done, and CALIPSO's CRC-16 is
:issue:`2970`; of the cryptographic half, ESP's is done and AH's (:issue:`2965`)
and HIP's (:issue:`2939`) are open.

These protocols parse a checksum or CRC field —
:class:`~pcapkit.protocols.link.gre.protocol.GRE`,
:class:`~pcapkit.protocols.internet.hip.protocol.HIP`,
:class:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT`,
:class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4`,
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`,
:class:`~pcapkit.protocols.internet.igmp.protocol.IGMP`,
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts`,
:class:`~pcapkit.protocols.internet.ipx.protocol.IPX`,
:class:`~pcapkit.protocols.internet.mh.protocol.MH`,
:class:`~pcapkit.protocols.application.ospf.protocol.OSPF`,
:class:`~pcapkit.protocols.transport.dccp.protocol.DCCP`,
:class:`~pcapkit.protocols.transport.sctp.protocol.SCTP`,
:class:`~pcapkit.protocols.transport.tcp.protocol.TCP` and
:class:`~pcapkit.protocols.transport.udp.protocol.UDP` — and SCTP checks whether
the value is *right*, through
:attr:`SCTP.checksum_valid <pcapkit.protocols.transport.sctp.protocol.SCTP.checksum_valid>`.
IPv4, OSPF, TCP, UDP and DCCP check it too, as do ICMP, ICMPv6, IGMP, GRE, MH and
HIP, as the one's-complement half below describes. The rest record the field and
never question it, so a corrupted capture parses as cleanly as an intact one:

* HOPOPT's and IPv6-Opts's is the CALIPSO option's CRC-16
  (:rfc:`5570#section-5.1.7`), which :issue:`2970` verifies and computes;
* IPX's is unused in practice, and its check is `Not Planned`_.

**These are different problems and they want separating**, because only one
of them is cryptographic and the distinction decides what is actually hard.

**The one's-complement Internet checksum**, which covers IPv4's header, TCP, UDP,
DCCP, ICMP/ICMPv6, IGMP, GRE, OSPF, MH and HIP, needs no cryptography: it is
sixteen-bit addition with end-around carry. The hard part is the **IP
pseudo-header**: the TCP, UDP, DCCP, ICMPv6, MH and HIP checksums cover source and
destination addresses, the protocol number and the payload length, all of which
live in the *enclosing* layer, so verification is a structural question about
:class:`~pcapkit.protocols.protocol.Protocol` rather than an arithmetic one.
SCTP has no such dependency: :rfc:`9260#section-6.8` defines its CRC32c over the
common header and chunks with the checksum field zeroed and **no pseudo-header**,
so the SCTP packet alone verifies it. Its CRC32c is a hand-rolled lookup table in
:mod:`pcapkit.protocols.transport.sctp.protocol`, not a library call, so it is no
precedent for a dependency either.

**The cryptographic integrity checks** are where the |cryptography|_
dependency — introduced for ESP — genuinely buys something new, and half of that
is already done. :class:`~pcapkit.protocols.internet.esp.protocol.ESP` **already verifies
its ICV** when a Security Association is supplied, and deliberately reports a
failure rather than raising, so a forged packet still parses and says so. What is
*not* done is **HIP**: its ``HIP_MAC``, ``HIP_MAC_2``, ``RVS_HMAC`` and
``RELAY_HMAC`` parameters, and its ``HIP_SIGNATURE`` and ``HIP_SIGNATURE_2``
parameters, are parsed into their data models and never checked against the
packet (:issue:`2939`). Verifying them needs a keying context in the shape ESP
already established through :mod:`pcapkit.corekit.context`, which is the reusable
part of the design rather than something to invent. Nor is
:class:`~pcapkit.protocols.internet.ah.protocol.AH`'s ICV checked: it is parsed as
octets, and verifying it needs that keying context plus the enclosing IP header,
whose immutable fields it covers (:rfc:`4302#section-3.3.3`), which is
:issue:`2965`.

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
  exact precedent in :class:`~pcapkit.protocols.internet.esp.protocol.ESPStatus`: an
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

**Checksum offload** was left to implementation, being about wording rather than
design. A capture taken on the sending host routinely holds checksums the NIC
had not computed, zero or garbage on the wire, so the status has to say *not
computed* distinctly from *wrong*, or it cries wolf on the commonest capture
there is. It is ``NOT_COMPUTED`` below, spelled after
:class:`~pcapkit.protocols.internet.esp.protocol.ESPStatus`'s ``NO_SA``.

**The one's-complement half is done** for every protocol whose checksum is
one's-complement (:issue:`2470`, :issue:`2472` to :issue:`2475`, :issue:`2489`,
:issue:`2618`, :issue:`2813`), on
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`
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
* **The IP layer owns the pseudo-header.** :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`
  and :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` verify their upper layer's
  checksum once parsed, and compute it for an upper layer constructed as their
  payload; ``make()`` of TCP, UDP, ICMPv6, MH and HIP also takes the ``pseudo``
  itself. MH's checksum is defined over IPv6 alone, so over IPv4 it is
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NO_PSEUDO_HEADER`.
* **Offload is** :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NOT_COMPUTED`,
  modelled on ``NO_SA``: a zero IPv4 or TCP checksum, or a TCP or UDP one holding
  the pseudo-header's sum alone, as Linux offload leaves it, never warns. So does
  a zero UDP checksum over IPv4 (:rfc:`768`), but not over IPv6, where it is
  mandatory (:rfc:`8200#section-8.1`).
* **A fragment is**
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NO_PSEUDO_HEADER`,
  atomic ones aside: TCP, UDP, ICMP, ICMPv6 and IGMP checksums cover all of the
  datagram's data, which it carries part of. OSPF's Packet Length says what its
  checksum covers, so it is verified when the fragment holds that much, and
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.TRUNCATED`
  otherwise.
* **IGMP covers the whole IP payload in every version, and GRE its header and
  payload only when** ``C`` **is set** (:rfc:`2236#section-2.5`,
  :rfc:`3376#section-4.1.2`, :rfc:`2784#section-2.5`). The IGMPv1 rule follows
  :rfc:`2236`, which updates :rfc:`1112`'s 8-octet one. A GRE header with ``C``
  clear is :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NOT_COMPUTED`,
  and ``make()`` computes one when ``checksum_present`` asks without giving it
  (:issue:`2618`). Neither GRE nor the Linux cooked-capture header carries a
  length, so a GRE message the capture cut short there is
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.TRUNCATED` by the
  original length its PCAP record or PCAP-NG packet block states (:issue:`2653`);
  behind IPv4 or IPv6, by the payload length they state (:issue:`2649`). An IPv4
  Total Length of 0 states none, so behind one, and through an AH after it, GRE,
  ICMP and IGMP go by the original length as well (:issue:`2689`). A GRE or IGMP
  header the data ends inside is
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.TRUNCATED` too
  (:issue:`2689`). Each of these cuts is recorded on the message's own header, so
  the message rebuilt on its own reads
  :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.TRUNCATED` as well, an
  ICMP one included (:issue:`2711`).
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

Deterministic Construction Arguments
------------------------------------

**Done** in 1.6.0 (:issue:`2594`): a ``make()`` call's argument list is
deterministic. Further proposals for the construction workflow go under this
heading.

Inferring a namespace from the caller's frame, for a conventional
four-argument group -- ``X``, ``X_default``, ``X_namespace`` and
``X_reversed`` -- leaves a call's contract invisible from its signature:
knowing what a bare string resolves against means knowing the convention and
trusting that every call site follows it exactly. :issue:`2356` and
:issue:`2394` are that inference failing, the first because an argument's own
default is ``None``, leaving nothing to anchor a namespace to, the second
because the name is a loop variable over a *list* parameter, which an
``isinstance(value, str)`` check on the arguments cannot see. Naming the enum
at each affected call site fixes an instance and leaves the mechanism as
fragile as it is.

So no ``make()`` infers a member from a string, ruled in review of :pr:`2593`
(:issue:`2489`): a field holding an enumeration takes the member or an
``int``, resolved with the enumeration's
:meth:`~pcapkit.corekit.enum.EnumLookup.get`. That settles a call's contract
at the signature, the way :func:`~pcapkit.corekit.infoclass.info_final` and
:func:`~pcapkit.protocols.schema.schema_final` settle a constructor's
keyword set once at class-definition time, and
:attr:`~pcapkit.protocols.protocol.Protocol.__own_make_keywords__`
(:issue:`2286`) which keywords a ``make()`` override owns. The pieces:

* :meth:`~pcapkit.protocols.protocol.Protocol._make_index` takes the value, the
  enumeration and the field's width, and returns what ``get`` resolves. A
  name, a :obj:`bool` for a field wider than one bit, and a code the field
  cannot carry raise :exc:`~pcapkit.utilities.exceptions.ProtocolError`, so
  every caller gets the range check :issue:`2617` asks for, with no masking.
  An option, a sub-option or a chunk given as a ``(code, arguments)`` pair
  resolves its code the same way.
* The ``X_default``, ``X_namespace`` and ``X_reversed`` keywords are removed
  in 1.6.0 with no deprecation period and no shim, ruled on :issue:`2594`;
  each class that shipped them records them under ``versionremoved``.
* The public wrapper is :meth:`Protocol.resolve_index
  <pcapkit.protocols.protocol.Protocol.resolve_index>`, which takes the group
  explicitly -- name, default, namespace, reversed -- so a caller holding a
  bare string resolves it first and passes the result to ``make()``. It is a
  static method every protocol inherits, beside
  :meth:`~pcapkit.protocols.protocol.Protocol.decode` and
  :meth:`~pcapkit.protocols.protocol.Protocol.unquote`, rather than a module of
  its own, since it serves ``make()`` alone.

The trade-off: the docs and the examples relied on a bare string for these
fields, so the change breaks every ``make()`` call site that relies on the
inference. That is why it is one change across :file:`pcapkit/protocols/`: it
removes the root cause of the :issue:`2356`/:issue:`2394` family rather than
leaving its next instance to be found and patched.

Not Planned
-----------

Asked for, and closed as ``wontfix`` for the reason given.

**Skipped by the owner** on :issue:`2805`:

* :issue:`3023` -- DSL: a physical layer with no frame format of its own; a DSL
  capture carries PPPoE, which is dissected, or ATM AAL5.
* :issue:`3024` -- ISDN: no single wire format, Q.921 LAPD and then Q.931's
  information elements, and no capture to test against.

**No format to decode**, so each stays generic or
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`:

* :issue:`3025` -- IPX's checksum: no document defines the algorithm, and the
  field reads ``0xFFFF``, not used, in practice.
* :issue:`3026` -- PCAP-NG's vendor block types: IRIG Timestamp and ARINC 429 are
  registered without a format, and Hone's and Sysdig's are defined only in those
  projects' sources.
* :issue:`3041` -- the IPv4 options ZSU, FINN, IMITD, ENCODE, VISA and DPS, and
  the :rfc:`4727` experiments: none has a public option layout.
* :issue:`3042` -- the TCP options Skeeter, Bubba, Trailer Checksum, SNAP and TCP
  Compression Filter: registered to people, with no document.
* :issue:`3043` -- IPv6 routing type 1, Nimrod: IANA cites no document, and
  Nimrod's specification defines no routing-header layout.
* :issue:`3044` -- ICMPv4 types 6 and 32: :rfc:`6918` records no public
  information on type 6, and type 32's only reference is a work in progress no
  archive holds.
* :issue:`3045` -- the SCTP PPIDs whose registration names no document, or only a
  project's sources or a site that does not resolve;
  :func:`~pcapkit.foundation.registry.protocols.transport.register_sctp` serves a
  user who has a definition.
* :issue:`3046` -- the Echo, Discard, Daytime and Character Generator PPIDs: their
  RFCs carry arbitrary octets, so ``Raw`` is already the complete reading.

**Reassembly behaviour kept as it is**:

* :issue:`3027` -- a default TCP reassembly timeout: no RFC sets one, a default
  would be invented and would split long-lived idle streams, and ``timeout``
  enables one on request.
* :issue:`3028` -- sending the ICMP Time Exceeded an expired IP buffer owes: an
  offline parser has nothing to send it on, so the buffer is released as
  :attr:`~pcapkit.foundation.reassembly.data.Completion.TIMEOUT` and the owed
  message is logged at debug.

**Third-party engine gaps**: those engines are best effort (:issue:`1687`), and
each of these gaps is structural, as the engine does not hand over what
:mod:`pcapkit`'s reassemblers and tracers read:

* :issue:`3029` -- reassembly on PyShark without a registered adapter: tshark
  reports dissected fields rather than octets.
* :issue:`3030` -- ``analyze`` on PyShark: it reads each flow's octets, which
  tshark does not hand over.
* :issue:`3031` -- reassembly and flow tracing on PyPCAP: pypcap does no
  dissection.
* :issue:`3032` -- reassembly and flow tracing on PCAP_CT: pcap-ct exposes
  pypcap's interface, so it has the same gap.
* :issue:`3033` -- IPv6 reassembly on PyPCAPFile: pypcapfile has no IPv6
  decoder.
* :issue:`3034` -- TCP over IPv6, behind a VLAN tag, in a tunnel or behind an
  extension header, on PyPCAPFile: pypcapfile decodes none of these carriers.
* :issue:`3035` -- tunnelled and extension-header traffic on DPKT: dpkt does not
  decode those chains, and walking them in the adapter was reverted under
  :issue:`1687`.
* :issue:`3036` -- the frames DPKT cannot decode: they are kept raw, so there is
  nothing to reassemble or trace.
* :issue:`3037` -- IPv6 past what Scapy dissects: scapy stops behind AH,
  Mobility, HIP and Shim6, and binds a BSD loopback family per host.
* :issue:`3038` -- DTLS reassembly on DPKT: it reads :mod:`pcapkit`'s own DTLS
  layer, which dpkt never produces.
* :issue:`3039` -- DTLS reassembly on Scapy: likewise, as scapy never produces
  that layer.
* :issue:`3040` -- DTLS reassembly on PyPCAPFile: likewise, as pypcapfile never
  produces that layer.

Remaining Work
--------------

The open work above, each item with its issue. Nothing here is claimed: to take
an item, say so on its issue.

* **The remaining protocols**, each with its issue under
  `More Protocols, More!!!`_.
* **SCTP**, under `SCTP`_ and `Reassembly Beyond IP and TCP`_: the remaining
  chunk codes (:issue:`2989`), every DATA and I-DATA chunk of a bundle dispatched
  (:issue:`2993`), and its user messages reassembled (:issue:`2935`). Its payload
  protocols are under `Registered, but Not Dissected`_.
* **ESP's algorithm coverage**, under `ESP`_: the registered transforms beyond
  AES-CBC, AES-GCM and the HMAC-SHA1 and HMAC-SHA2 truncations (:issue:`2958`,
  :issue:`3009`), and Extended Sequence Numbers with the implicit-IV transforms
  (:issue:`2963`).
* **Integrity verification**, under `Checksum and Integrity Verification`_: AH's
  ICV (:issue:`2965`), HIP's MAC and signature parameters (:issue:`2939`), and
  the CALIPSO option's CRC-16 (:issue:`2970`).
* **TLS and DTLS**, under `DTLS`_: records split across TCP segments
  (:issue:`2938`), the remaining extensions (:issue:`2966`), handshake bodies
  beyond the hellos and the heartbeat and ACK records (:issue:`2969`), and
  NGAP's and the other PPIDs carried over DTLS (:issue:`2971`).
* **Flow tracing beyond TCP** (:issue:`2956`) and the mid-connection reuse case
  (:issue:`2962`), under `Reassembly Beyond IP and TCP`_.
* **IP reassembly**: unfragmented IPv4 datagrams, which want a ruling first
  (:issue:`2961`), under `Maybe Even Faster?`_; and buffers sized to the
  fragments they hold (:issue:`2957`), under `Reassembly Beyond IP and TCP`_.
* **The Mobility Header option-payload registry**, under `Mobility Header`_
  (:issue:`2937`), and the dissectors it would register: the MLD and IGMPv3
  records of the multicast options (:issue:`2994`) and the :rfc:`6088` traffic
  selectors (:issue:`2990`).
* **Bindings**, under `Registered, but Not Dissected`_: the 802.11 frame body
  (:issue:`2936`, :issue:`2975`), L2TPv3 (:issue:`2976`) and L2F
  (:issue:`3011`), TCP 8443 (:issue:`3017`), and DCCP's ports (:issue:`2999`).
* **IPv6's Traffic Class**, split into DSCP and ECN (:issue:`3000`), under
  `More Protocols, More!!!`_.
* **Per-entry coverage of the option and parameter registries**, below.
* **The test suite**, under `Test Cases`_: a pin on everything not yet dissected
  (:issue:`3008`), and the suite shipped in the wheel (:issue:`3022`).
* **Iterative dissection**, under `Recursive Dissection, With a Depth Limit`_,
  whose issue is not filed yet.

**Per-entry coverage of the option and parameter registries.** The option,
parameter, block and frame registries are *enumerated* but not *implemented*
throughout: a code can be registered and named, and still have no per-entry
read/make pair behind it. The goal is to close that gap for every code whose
format is specified, and `Not Planned`_ lists the codes without one. The planned
ones:

* TLS extensions (:issue:`2966`), PPP's control protocols (:issue:`2978`), and
  the MPLS label stack behind PPP and Ethernet (:issue:`3013`);
* ICMPv4 message types (:issue:`2983`), and ICMPv6's beyond Neighbor Discovery
  (:issue:`2986`) with RPL (:issue:`2991`);
* IPv4 options (:issue:`2997`), IPv6 options (:issue:`2996`) and routing types
  (:issue:`2984`), and HIP's parameters (:issue:`3006`);
* TCP options (:issue:`2987`), DCCP options (:issue:`2999`) and SCTP's chunk
  codes (:issue:`2989`);
* DNS RR types and EDNS options (:issue:`3002`), and HTTP/2 frame types
  (:issue:`3003`).

Both halves of the gap are measurable, against the families
:file:`examples/generators/options.py` walks and the ``EXPECTED_FAILURES`` of
:file:`tests/protocols/test_option_roundtrip_unit.py`:

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

Two things to be precise about. The round-trip half is closed:
``EXPECTED_FAILURES`` is empty, so a new entry there records a defect rather than
a deferral. And **round-tripping is not the same as being implemented**: the
harness walks the codes each protocol registers a handler for, not every code
its enumeration names, so what remains is the codes with no per-entry handler,
such as the SCTP chunk types under `SCTP`_ above, which parse as opaque.

This is deliberately **not** the same request as the ``__proto__`` dispatch
registries. Those name whole protocols, so closing a gap there means writing a
dissector, which is the protocol work above. The option and parameter
registries are per-entry formats inside protocols that already exist, so the
work is self-contained. Their harness already fails when a registered code has
no case; what is missing is the implementations behind the codes, not the
accounting of them.
:file:`tests/protocols/test_dispatch_registry_unit.py` gives the ``__proto__``
family the same accounting for whether a registered protocol's dispatch reaches
it.
