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

The base deliberately carries **no header parsing at all**, in the way
:class:`~pcapkit.protocols.internet.ip.IP` carries none for its family. That is
not tidiness: the versions genuinely do not share a header. All that is common
across them is the *first 16-bit word carrying a version nibble at bits 12-15*;
everything after it differs, so a base that parsed further would be assuming one
version's layout for all of them.

What the family still wants
---------------------------

**L2TPv3** [:rfc:`3931`] has a different session header and a different control
message header from v2, and is reachable two ways -- over UDP port 1701 like v2,
and directly over IP as **protocol number 115**. That second route is why
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
leaves 115 unbound today: the binding waits on an ``L2TPv3`` class, not on a
different framing decision. It also means v3 is the first member of this family
to have a real :meth:`~pcapkit.protocols.protocol.Protocol.__index__`, and so
the first that must have a module of its own under the project's one-module-per-index
rule.

**L2F** [:rfc:`2341`] is reached when the version nibble reads ``1``. It is *not*
an earlier version of L2TP: :rfc:`2661` §3.1 requires ``Ver`` to be 2 and reserves
the value 1 "to permit detection of L2F packets should they arrive intermixed with
L2TP packets". L2F is a separate protocol with its own header. It is therefore to
be implemented as ``L2F``, the canonical name, carrying ``L2TPv1`` only as an
alias in its :meth:`~pcapkit.protocols.protocol.Protocol.id` -- the same
relationship HTTP/3 has to QUIC. c.f.
:meth:`HTTPv1.id <pcapkit.protocols.application.httpv1.HTTP.id>` for how a
version-flavoured alias is spelled: canonical name first, alias second, since
callers take element zero as canonical.

Selecting a version
-------------------

Nothing dispatches on the version nibble yet, because only one version exists.
When a second lands, the mechanism it wants already has a precedent in
:class:`~pcapkit.protocols.application.http.HTTP`, which reads a version and
delegates to a per-version class. L2TP is the easier case:
:meth:`HTTP._guess_version <pcapkit.protocols.application.http.HTTP._guess_version>`
has to *trial-parse* each candidate because the wire format carries no version
field, whereas L2TP states its version explicitly in those four bits. So a
deterministic switch on ``Ver`` is enough, and no new registry is needed.

.. autoclass:: pcapkit.protocols.link.l2tp.L2TP
   :no-members:
   :show-inheritance:

   .. autoproperty:: info_name

   .. automethod:: id

   .. automethod:: __index__

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
