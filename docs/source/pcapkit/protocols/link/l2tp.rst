L2TP - Layer Two Tunnelling Protocol
====================================

.. module:: pcapkit.protocols.link.l2tp
.. module:: pcapkit.protocols.link.l2tp.protocol

:mod:`pcapkit.protocols.link.l2tp.protocol` contains
:class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` only, an abstract base class for the
Layer Two Tunnelling Protocol family [*]_. The concrete versions live in modules
of their own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
   * - L2TPv2
     - :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`
     - :rfc:`2661`

The base parses no header, as :class:`~pcapkit.protocols.internet.ip.protocol.IP`
does for its family: only the first 16-bit word, with the version nibble at bits
12-15, is common to every version, so parsing further would impose one version's
layout on all.

.. autoclass:: pcapkit.protocols.link.l2tp.protocol.L2TP
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
leaves 115 unbound: the binding waits on an ``L2TPv3`` class. Protocol 115 names v3
alone: v2's :meth:`~pcapkit.protocols.protocol.Protocol.__index__` is its UDP
port.

**L2F** [:rfc:`2341`] is reached when the version nibble reads ``1``. It is *not*
an earlier version of L2TP: :rfc:`2661` §3.1 requires ``Ver`` to be 2 and reserves
the value 1 "to permit detection of L2F packets should they arrive intermixed with
L2TP packets". L2F is a separate protocol with its own header, so it is to be
implemented as ``L2F``, the canonical name, with ``L2TPv1`` only as an alias in its
:meth:`~pcapkit.protocols.protocol.Protocol.id`. See
:meth:`L2TPv2.id <pcapkit.protocols.link.l2tpv2.protocol.L2TPv2.id>` for
how a version-flavoured alias is spelled: canonical name first, alias second,
since callers take element zero as canonical.

Version Dispatch
----------------

Constructing the base gives the member its ``version`` field names, from octets or
from fields; without it, octets give the one their version nibble names, and fields
are refused, since no field picks a member (:issue:`2574`).
:meth:`~pcapkit.protocols.link.l2tp.protocol.L2TP._member_of_version` maps ``2`` to
:class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` and refuses any other version, for
that field, for the nibble and for the data
:meth:`~pcapkit.protocols.link.l2tp.protocol.L2TP.from_data` is handed. UDP port 1701 binds
L2TPv2 itself. A further member goes in that switch, and binding the port to the
base through a hook making the same switch, as
:meth:`IGMP._dispatch <pcapkit.protocols.internet.igmp.protocol.IGMP._dispatch>` does for
IP protocol 2, needs no new registry. Unlike
:class:`~pcapkit.protocols.application.http.protocol.HTTP`, whose
:meth:`~pcapkit.protocols.application.http.protocol.HTTP._guess_version` has to *infer*
the version, L2TP states it in the version nibble.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
