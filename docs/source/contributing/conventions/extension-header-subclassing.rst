.. _extension-header-subclassing:

Extension-Header Base Classes
-----------------------------

Every IPv6 extension header in this package subclasses
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`. Some name a **second** base
as well, and which ones do is a ruling rather than an accident. The owner ruled, in
review of the rename that made :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` the
shared base (:issue:`917`), that a header usable *only* as an extension header inherits
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` and nothing else --
:class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag` being the example -- while one
that is usable as a standalone protocol in its own right inherits both
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` and
:class:`~pcapkit.protocols.internet.internet.Internet` (or
:class:`~pcapkit.protocols.internet.ipsec.IPsec`), as
:class:`~pcapkit.protocols.internet.esp.ESP` does.

The family as it stands:

.. list-table::
   :header-rows: 1
   :widths: 34 30 36

   * - Header
     - Bases
     - Classification
   * - :class:`~pcapkit.protocols.internet.hopopt.HOPOPT`,
       :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`,
       :class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`,
       :class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`,
       :class:`~pcapkit.protocols.internet.mh.MH`
     - :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
     - extension-header only
   * - :class:`~pcapkit.protocols.internet.ah.AH`,
       :class:`~pcapkit.protocols.internet.esp.ESP`
     - :class:`~pcapkit.protocols.internet.ipsec.IPsec`,
       :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
     - **also standalone**
   * - :class:`~pcapkit.protocols.internet.hip.HIP`
     - :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`,
       :class:`~pcapkit.protocols.internet.internet.Internet`
     - **also standalone**

:class:`~pcapkit.protocols.internet.ipsec.IPsec` is itself an
:class:`~pcapkit.protocols.internet.internet.Internet` subclass, which is the
parenthetical :class:`~pcapkit.protocols.internet.ipsec.IPsec` alternative in the ruling:
naming it satisfies the convention, and it is the right second base for a header whose
standalone form is an IPsec one.

The Shared-Registry Trap
~~~~~~~~~~~~~~~~~~~~~~~~

**Stated before the criterion itself, because it is the part a future reader will get
wrong.** The obvious way to decide whether a header is "usable as a standalone protocol"
is to ask what the library's own dispatch already allows. That answer is useless, and
measurably so:

.. code-block:: pycon

   >>> from pcapkit.protocols.internet.ipv4 import IPv4
   >>> from pcapkit.protocols.internet.internet import Internet
   >>> IPv4.__proto__ is Internet.__proto__
   True

The protocol-number registry is **one shared object**, so *every* extension header
is reachable as an IPv4 payload in this library --
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT` and
:class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag` included. Registry
membership therefore says nothing at all about standalone-ness, and a classification
derived from it would make every one of them standalone.

Nor does IANA's *IPv6 Extension Header Types* registry discriminate: it lists every
one of the implemented headers, plus ``Shim6`` (140) and 253/254. Being *in* that
registry is what makes something an extension header; it is not evidence about
whether the same header is also a protocol in its own right.

The IPv4-Payload Test
~~~~~~~~~~~~~~~~~~~~~

So the census is read out of the specifications, on the owner's instruction: work
through the RFCs to establish, for each defined IPv6 extension header, whether it is
extension-header-only or a standalone protocol as well, and decide from that whether it
inherits :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` alone or names additional bases.

And the limb that decides is **whether a primary source shows the header carried
directly as an IPv4 payload**:

*  :class:`~pcapkit.protocols.internet.ah.AH` -- :rfc:`4302#section-3.1.1`, *"In the
   context of IPv4, this calls for placing AH after the IP header"*, with a
   before-and-after IPv4 diagram.
*  :class:`~pcapkit.protocols.internet.esp.ESP` -- :rfc:`4303#section-3.1.1`, the
   same sentence and the same diagram for ESP.
*  :class:`~pcapkit.protocols.internet.hip.HIP` -- :rfc:`7401#appendix-C.2`,
   *"IPv4 HIP Packet (I1 Packet)"*, whose worked checksum is over an IPv4 header
   carrying ``Next Header: 139``. :rfc:`7401#section-5.1` also calls the HIP header
   *"logically an IPv6 extension header"*, so HIP is genuinely both.

:class:`~pcapkit.protocols.internet.mh.MH` is the instructive failure, because it
**is** a protocol in its own right and still does not qualify:
:rfc:`6275#section-6.1.1` defines its checksum over a pseudo-header of *"IPv6 header
fields"* whose addresses are *"the addresses that appear in the Source and
Destination Address fields in the IPv6 packet carrying the Mobility Header"* -- there
is no IPv4 variant of that computation -- and the IPv4 equivalent function is not
protocol 135 at all, since :rfc:`5944` carries Mobile IPv4 over UDP port 434.
``Shim6`` (140) has the same shape and the same verdict; this package carries no parser
class for it, so nothing implements the classification, but a future one inherits
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` alone.

.. important::

   Own-protocolhood on its own is **not** sufficient, and MH is the case that
   settles it: the alternative reading -- that a protocol in its own right qualifies
   whether or not it can appear under IPv4 -- was put to the owner explicitly in
   review of :issue:`917` and not
   taken, so MH and ``Shim6`` stay extension-only. A header that is a protocol in its
   own right but structurally cannot be an IPv4 payload names
   :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` alone.

Explicit Base Declarations
~~~~~~~~~~~~~~~~~~~~~~~~~~

Name the second base **explicitly**, even where it is already in the MRO.
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` derives
:class:`~pcapkit.protocols.internet.internet.Internet`, so every extension header
reaches :class:`~pcapkit.protocols.internet.internet.Internet` transitively and an
``__mro__`` check cannot tell the two groups apart. The declaration is the only place the
classification exists, which is why ``tests/protocols/internet/test_ipv6_ext_unit.py``
pins it against ``__bases__``:

.. code-block:: python

   STANDALONE_MEMBERS = frozenset({'AH', 'ESP', 'HIP'})

Add a header to that set in the same change that adds its second base, and keep the
RFC ground in the ``#:`` comment beside it. The test walks
``IPv6_Ext.__subclasses__()`` rather than a hard-coded list, so any further header is
held to the convention whether or not anyone remembers this page.

ESP's Two Facts
~~~~~~~~~~~~~~~

Two facts about :class:`~pcapkit.protocols.internet.esp.ESP` coexist, and each is
routinely mistaken for a refutation of the other.

**It is an extension header.** IANA's *IPv6 Extension Header Types* registry lists
protocol number **50**, and this package's
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` agrees (``ESP = 50``).
:rfc:`8200#section-4.5` appears to say otherwise -- *"the Encapsulating Security
Payload (ESP) is not considered an extension header"* -- but that sentence opens
*"For this purpose,"*, scoping it to the fragmentation discussion it sits in, and the
sentence after it lists ESP among *"examples of upper-layer headers"*. The library
follows the registry, on the owner's ruling for
:issue:`895`, which is why ESP
carries the same extension-mode contract as its siblings.

**And it terminates the chain walk.** :rfc:`4303` places ESP's Next Header byte
inside the *encrypted* trailer, so with no key material there is nothing to continue
on: ESP's own data model reports ``next`` as :obj:`None`, and
:meth:`IPv6._decode_next_layer <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`
ends the ordinary way one iteration later -- not because ESP lacks a parser, which
it has, but because it cannot hand the walk a successor.

The full reasoning, including how ESP's terminal case differs from 253/254's, is
written where the code is and is deliberately not restated at length here: see
:meth:`IPv6._import_next_layer <pcapkit.protocols.internet.ipv6.IPv6._import_next_layer>`
and the module docstring of :mod:`pcapkit.protocols.internet.ipv6_ext`.

.. caution::

   The two facts have to be kept apart when reading any of this. "ESP is not an
   extension header" (wrong, and :rfc:`8200#section-4.5` quoted out of scope) is a
   different claim from "ESP cannot be walked past" (right, and about
   :rfc:`4303`'s wire format). Collapsing them is how ESP ends up either dropped
   from the extension-header contract or wrongly walked past.
