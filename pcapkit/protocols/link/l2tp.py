# -*- coding: utf-8 -*-
"""L2TP - Layer Two Tunnelling Protocol
==========================================

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

Only L2TPv2 is implemented. What the family is expected to grow is set out below,
so that the base's shape is not guessed at later.

The base deliberately carries **no header parsing at all**, in the way
:class:`~pcapkit.protocols.internet.ip.IP` carries none for its family. That is
not tidiness: the versions genuinely do not share a header. All that is common
across them is the *first 16-bit word carrying a version nibble at bits 12-15*;
everything after it differs, so a base that parsed further would be assuming one
version's layout for all of them.

What the family still wants
---------------------------

**L2TPv3** [:rfc:`3931`] has a different session header and a different control
message header from v2, and is reachable two ways -- over UDP port 1701 like v2
(§4.1.2), and directly over IP as **protocol number 115** (§4.1.1: *"L2TPv3 over
IP (both versions) utilizes the IANA-assigned IP protocol ID 115"*). That second
route is why
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
leaves 115 unbound today: the binding waits on an ``L2TPv3`` class, not on a
different framing decision. It also means v3 is the first member of this family
to have a real :meth:`~pcapkit.protocols.protocol.Protocol.__index__`.

GitHub issue #548 proposed closing that gap by binding
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` at 115 instead, which does not
work and is worth recording so it is not proposed again. Over IP the v3 session
header is, in :rfc:`3931` §4.1.1's own words, *"free of any restrictions imposed
by coexistence with L2TPv2 and L2F"* -- a data message opens with the raw 32-bit
Session ID and carries **no version nibble at all**, so there is nothing a v2
parser could even test to recognise that the datagram is not its own. Measured,
that binding reported ``version=4``, ``tunnelid=0x5678`` and ``sessionid=0xff03``
for a v3-over-IP datagram: a complete header assembled out of the top half of a
Session ID and the first two octets of the PPP frame behind it. 115 is a missing
*class*, not a missing registration, and until that class exists an undissected
payload is the honest answer.

**L2F** [:rfc:`2341`] is reached when the version nibble reads ``1``. It is *not*
an earlier version of L2TP: :rfc:`2661` §3.1 requires ``Ver`` to be 2 and reserves
the value 1 "to permit detection of L2F packets should they arrive intermixed
with L2TP packets". L2F is a separate protocol with its own header. It is
therefore to be implemented as ``L2F``, the canonical name, carrying ``L2TPv1``
only as an alias in its :meth:`~pcapkit.protocols.protocol.Protocol.id` --
the same relationship HTTP/3 has to QUIC. c.f.
:meth:`HTTPv1.id <pcapkit.protocols.application.httpv1.HTTP.id>` for how a
version-flavoured alias is spelled: canonical name first, alias second, since
callers take element zero as canonical.

Selecting a version
-------------------

Nothing *dispatches* on the version nibble yet, because only one version exists
-- but :meth:`L2TPv2.read <pcapkit.protocols.link.l2tpv2.L2TPv2.read>` does
**check** it, and refuses anything other than ``2``. That is the half of the
mechanism which is useful with one version implemented: it keeps v3 traffic on
port 1701 (:rfc:`3931` §4.1.2 shares the port, so this is ordinary capture
traffic rather than a corner case) from being reported as v2 with a tunnel and
session ID read out of v3's Control Connection ID.

When a second version lands, the remaining half -- delegation rather than refusal
-- already has a precedent in
:class:`~pcapkit.protocols.application.http.HTTP`, which reads a version and
delegates to a per-version class. L2TP is the easier case: HTTP has to
*trial-parse* each candidate in
:meth:`~pcapkit.protocols.application.http.HTTP._guess_version` because the wire
format carries no version field, whereas L2TP states its version explicitly in
those four bits. So a deterministic switch on ``Ver`` is enough, and no new
registry is needed -- the class bound at UDP 1701 reads two octets, masks out the
nibble, and hands the datagram to the matching class. Note the switch belongs on
the **UDP** path only: over IP protocol 115 there is no nibble to switch on, per
the §4.1.1 note above.

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.protocols.link.link import Link
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import NoReturn

    from typing_extensions import Literal

__all__ = ['L2TP']


class L2TP(Link[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """This class implements all protocols in L2TP family.

    - Layer Two Tunnelling Protocol version 2
      (:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`) [:rfc:`2661`]

    It is abstract for the same mechanical reason
    :class:`~pcapkit.protocols.internet.ip.IP` is:
    :attr:`~pcapkit.protocols.protocol.Protocol.name` and
    :meth:`~pcapkit.protocols.protocol.Protocol.read` are both declared
    abstract by :class:`~pcapkit.protocols.protocol.ProtocolBase` and neither is
    defined here, so the class cannot be instantiated. Bind a version, never this
    class.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    #: NOTE: Declared on the base, and so shared by every version, deliberately.
    #: This is the key the parsed datagram appears under, and a consumer wants
    #: ``udp.l2tp`` whichever version was on the wire -- the version is reported
    #: by :attr:`~pcapkit.protocols.protocol.Protocol.alias` instead. Left to
    #: the class-name default it would read ``l2tpv2``, ``l2tpv3`` and so on, and
    #: every consumer would have to know the version to find the data.
    @property
    def info_name(self) -> 'Literal["l2tp"]':
        """Key name of the :attr:`info` dict."""
        return 'l2tp'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["L2TP"], Literal["L2TPv2"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol -- the family name, then every version in
            it, as :meth:`HTTP.id <pcapkit.protocols.application.http.HTTP.id>`
            does for its own family. ``L2F`` and ``L2TPv3`` join this tuple when
            they are implemented.

        """
        return ('L2TP', 'L2TPv2')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        Note:
            An abstract base is reached by nothing, so it has no index of its
            own. That is also the project's rule for module layout -- a distinct
            ``__index__`` means a distinct module, and a base carrying none
            claims no module of its own beyond holding the family together.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')
