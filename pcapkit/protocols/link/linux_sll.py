# -*- coding: utf-8 -*-
"""LINUX_SLL - Linux "Cooked" Capture Encapsulation Family
==============================================================

.. module:: pcapkit.protocols.link.linux_sll

:mod:`pcapkit.protocols.link.linux_sll` contains
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` only, the base class of
:class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1` and
:class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`.

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.const.linux.arphrd import ARPHRD
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.fields.numbers import EnumField
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['LinuxSLL']

#: Resolves ``protocol_type`` exactly as
#: :class:`~pcapkit.protocols.schema.link.ethernet.Ethernet` resolves its ``type``.
_ETHERTYPE_FIELD = EnumField(length=2, namespace=Enum_EtherType)

#: ``arphrd_type`` values whose ``protocol_type`` is not an EtherType, per
#: tcpdump.org's LINUX_SLL and LINUX_SLL2 pages.
_ARPHRD_NOT_ETHERTYPE = frozenset({
    ARPHRD.FRAD,
    ARPHRD.IPGRE,
    ARPHRD.IEEE80211_RADIOTAP,
    ARPHRD.IP6GRE,
    ARPHRD.NETLINK,
})


def _resolve_next_layer_proto(arphrd_type: 'int',
                              protocol_type: 'int') -> 'Enum_EtherType | int':
    """Resolve the next-layer dispatch key of either version.

    Args:
        arphrd_type: ARP hardware type of the interface the packet was seen on.
        protocol_type: Protocol (internet layer), as parsed off the wire.

    Returns:
        ``protocol_type`` itself if ``arphrd_type`` is in
        :data:`_ARPHRD_NOT_ETHERTYPE`; otherwise the value
        :class:`~pcapkit.protocols.link.ethernet.Ethernet` stores for the same
        ``type``.

    """
    if int(arphrd_type) in _ARPHRD_NOT_ETHERTYPE:
        return protocol_type
    return _ETHERTYPE_FIELD.post_process(protocol_type, {})


def _validate_link_addr(alias: 'str', link_addr: 'bytes | bytearray',
                        link_addr_length: 'Optional[int]', *,
                        max_length: 'int') -> 'tuple[bytes, int]':
    """Validate and pad the link-layer address for ``make()`` of either version.

    Args:
        alias: Acronym of the calling protocol, for the error message.
        link_addr: Link-layer address, at most 8 octets.
        link_addr_length: Length in use, by default ``len(link_addr)``; may
            exceed 8, e.g. 20 for InfiniBand, of which the header keeps 8.
        max_length: Maximum of the wire field holding the length.

    Returns:
        ``link_addr`` padded with ``NUL`` octets to 8, and the length.

    Raises:
        ProtocolError: If ``link_addr`` exceeds 8 octets, or the length is
            outside ``0`` to ``max_length``.

    """
    _addr = bytes(link_addr)
    if len(_addr) > 8:
        raise ProtocolError(f'{alias}: invalid link-layer address: {link_addr!r}, '
                            f'must fit in 8 octets')
    if link_addr_length is None:
        link_addr_length = len(_addr)
    elif not 0 <= link_addr_length <= max_length:
        raise ProtocolError(f'{alias}: invalid link-layer address length: {link_addr_length!r}, '
                            f'must be between 0 and {max_length}')
    return _addr.ljust(8, b'\x00'), link_addr_length


class LinuxSLL(Link[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Base class of the Linux "cooked" capture encapsulation family.

    The versions differ in field order and width, so this base holds only the
    next-layer dispatch they share. See :ref:`linux-sll-labels` for the labels
    that select a version.

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["LinuxSLL1"], Literal["LinuxSLL2"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol: the direct members, each by its own name.

        """
        return ('LinuxSLL1', 'LinuxSLL2')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: The family base has no registry entry; nothing
                dispatches to it, only to its members.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack
                <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of next layer: :class:`~pcapkit.protocols.link.netlink.Netlink`
            when ``arphrd_type`` is :attr:`ARPHRD.NETLINK
            <pcapkit.const.linux.arphrd.ARPHRD.NETLINK>`; otherwise
            :class:`~pcapkit.protocols.misc.raw.Raw`, recording ``proto``, for
            every other ``arphrd_type`` in :data:`_ARPHRD_NOT_ETHERTYPE`.

        """
        file_ = self._get_payload()
        if length is None:
            length = len(file_)
        arphrd_type = int(self.__header__.arphrd_type)  # type: ignore[attr-defined]
        if not min(length, len(file_)):
            return super()._import_next_layer(proto, length, packet=packet)  # type: ignore[misc,call-arg]

        if arphrd_type == ARPHRD.NETLINK:
            from pcapkit.protocols.link.netlink import Netlink  # pylint: disable=import-outside-toplevel # isort: skip
            return self._parse_next_layer(Netlink, file_, length, alias=proto, packet=packet,
                                          layer=self._exlayer, protocol=self._exproto,
                                          __context__=self._exctx)

        if arphrd_type not in _ARPHRD_NOT_ETHERTYPE:
            return super()._import_next_layer(proto, length, packet=packet)  # type: ignore[misc,call-arg]

        from pcapkit.protocols.misc.raw import Raw  # pylint: disable=import-outside-toplevel # isort: skip
        return self._parse_next_layer(Raw, file_, length, alias=proto, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      __context__=self._exctx)
