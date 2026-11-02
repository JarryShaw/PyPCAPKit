L2TP - Layer Two Tunnelling Protocol
====================================

.. module:: pcapkit.protocols.link.l2tp

:mod:`pcapkit.protocols.link.l2tp` contains
:class:`~pcapkit.protocols.link.l2tp.L2TP` only, an abstract base class for the
Layer Two Tunnelling Protocol family [*]_. The concrete versions live in modules
of their own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
   * - L2TPv2
     - :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`
     - :rfc:`2661`

Only L2TPv2 is implemented.

The base deliberately parses no header, as
:class:`~pcapkit.protocols.internet.ip.IP` does for its family, because the
versions do not share one. Only the first 16-bit word, with a version nibble at
bits 12-15, is common to all of them; a base that parsed further would assume one
version's layout for every version.

.. autoclass:: pcapkit.protocols.link.l2tp.L2TP
   :no-members:
   :show-inheritance:

   .. autoproperty:: info_name

   .. automethod:: id
   .. automethod:: from_data

   .. automethod:: __index__
   .. automethod:: __new__

   .. automethod:: _member_of_version

Versions Not Implemented
------------------------

**L2TPv3** [:rfc:`3931`] has a different session header and control message
header from v2, and is reachable two ways: over UDP port 1701 like v2, and
directly over IP as **protocol number 115**. That second route is why
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
leaves 115 unbound: the binding waits on an ``L2TPv3`` class. It would also be
the first member of this family with a real
:meth:`~pcapkit.protocols.protocol.Protocol.__index__`.

**L2F** [:rfc:`2341`] is reached when the version nibble reads ``1``. It is *not*
an earlier version of L2TP: :rfc:`2661` §3.1 requires ``Ver`` to be 2 and reserves
the value 1 "to permit detection of L2F packets should they arrive intermixed with
L2TP packets". L2F is a separate protocol with its own header, so it is to be
implemented as ``L2F``, the canonical name, with ``L2TPv1`` only as an alias in its
:meth:`~pcapkit.protocols.protocol.Protocol.id`. See
:meth:`L2TPv2.id <pcapkit.protocols.link.l2tpv2.L2TPv2.id>` for
how a version-flavoured alias is spelled: canonical name first, alias second,
since callers take element zero as canonical.

Version Dispatch
----------------

Constructing the base gives the member its ``version`` field names, from octets or
from fields; without it, octets give the one their version nibble names, and fields
are refused, since no field picks a member (:issue:`2574`).
:meth:`~pcapkit.protocols.link.l2tp.L2TP._member_of_version` maps ``2`` to
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` and refuses any other version, for
that field, for the nibble and for the data
:meth:`~pcapkit.protocols.link.l2tp.L2TP.from_data` is handed. UDP port 1701 binds
L2TPv2 itself, the only member. The switch is where a further member goes, and
binding the port to the base through a hook making the same switch, as
:meth:`IGMP._dispatch <pcapkit.protocols.internet.igmp.IGMP._dispatch>` does for
IP protocol 2, needs no new registry. L2TP is the easier case beside
:class:`~pcapkit.protocols.application.http.HTTP`, whose
:meth:`~pcapkit.protocols.application.http.HTTP._guess_version` has to *infer*
the version, because HTTP's wire format carries no version field, whereas L2TP
states its version explicitly in those four bits.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
