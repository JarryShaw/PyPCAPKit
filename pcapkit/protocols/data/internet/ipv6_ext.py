# -*- coding: utf-8 -*-
"""data model for generically-parsed IPv6 extension headers"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.ipv6.extension_header import ExtensionHeader
    from pcapkit.const.reg.transtype import TransType

__all__ = ['IPv6_Ext']


@info_final
class IPv6_Ext(Protocol):
    """Data model for a generically-parsed IPv6 extension header.

    See :class:`pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
    for how each field below is derived.

    """

    #: The extension header this instance stands in for -- the numeric code
    #: the caller dispatched on, resolved to its
    #: :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` member.
    #: :data:`None` when ``alias`` was not given or named no such member
    #: (:meth:`read <pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.read>`
    #: sets it so in both cases, and the class property at
    #: :attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protocol`
    #: is typed to match).
    protocol: 'Optional[ExtensionHeader]'
    #: Next header, parsed off the wire. :data:`None` when the declared
    #: length would have overrun what remained and the walk stopped instead
    #: of trusting it.
    next: 'Optional[TransType]'
    #: Next header as declared on the wire. Equal to :attr:`next` except on
    #: an overrun, where :attr:`next` is :data:`None` but this keeps the
    #: octet so that a rebuild reproduces it.
    declared_next: 'TransType'
    #: Raw ``Hdr Ext Len`` octet, as on the wire.
    len: 'int'
    #: Length of this extension header, in octets, actually consumed.
    length: 'int'
    #: Header-specific content after the two fixed octets, as consumed.
    data: 'bytes'
    #: Original parsing error, if this instance was reached as a
    #: :func:`~pcapkit.utilities.decorators.beholder` fallback rather than by
    #: direct dispatch.
    error: 'Optional[Exception]'
