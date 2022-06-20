# -*- coding: utf-8 -*-
"""IPv6-Frag - Fragment Header for IPv6
==========================================

:mod:`pcapkit.protocols.internet.ipv6_frag` contains
:class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`
only, which implements extractor for Fragment Header for
IPv6 (IPv6-Frag) [*]_, whose structure is described as
below:

======= ========= ==================== =======================
Octets      Bits        Name                    Description
======= ========= ==================== =======================
  0           0   ``frag.next``               Next Header
  1           8                               Reserved
  2          16   ``frag.offset``             Fragment Offset
  3          29                               Reserved
  3          31   ``frag.mf``                 More Flag
  4          32   ``frag.id``                 Identification
======= ========= ==================== =======================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Fragment

"""
from typing import TYPE_CHECKING, overload

from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.protocols.data.internet.ipv6_frag import IPv6_Frag as DataType_IPv6_Frag
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, BinaryIO, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import Protocol

__all__ = ['IPv6_Frag']


class IPv6_Frag(Internet[DataType_IPv6_Frag]):
    """This class implements Fragment Header for IPv6."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Fragment Header for IPv6"]':
        """Name of current protocol."""
        return 'Fragment Header for IPv6'

    @property
    def alias(self) -> 'Literal["IPv6-Frag"]':
        """Acronym of corresponding protocol."""
        return 'IPv6-Frag'

    @property
    def length(self) -> 'Literal[8]':
        """Header length of current protocol."""
        return 8

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protocol(self) -> 'Optional[str] | NoReturn':
        """Name of next layer protocol (if any).

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")
        return super().protocol

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, extension: 'bool' = False,  # pylint: disable=arguments-differ
             **kwargs: 'Any') -> 'DataType_IPv6_Frag':  # pylint: disable=unused-argument
        """Read Fragment Header for IPv6.

        Structure of IPv6-Frag header [:rfc:`8200`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Identification                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            extension: If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _temp = self._read_fileng(1)
        _offm = self._read_binary(2)
        _ipid = self._read_unpack(4)

        ipv6_frag = DataType_IPv6_Frag(
            next=_next,
            offset=int(_offm[:13], base=2),
            mf=bool(int(_offm[15], base=2)),
            id=_ipid,
        )

        if extension:
            return ipv6_frag
        return self._decode_next_layer(ipv6_frag, _next, length - self.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[BinaryIO]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.

        Keyword Args:
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object."""
        return 8

    @classmethod
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.IPv6_Frag  # type: ignore[return-value]
