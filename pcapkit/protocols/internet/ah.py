# -*- coding: utf-8 -*-
"""AH - Authentication Header
================================

.. module:: pcapkit.protocols.internet.ah

:mod:`pcapkit.protocols.internet.ah` contains
:class:`~pcapkit.protocols.internet.AH` only,
which implements extractor for Authentication
Header (AH) [*]_, whose structure is described
as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``ah.next``               Next Header
  1           8   ``ah.length``             Payload Length
  2          16                             Reserved (must be zero)
  4          32   ``ah.spi``                Security Parameters Index (SPI)
  8          64   ``ah.seq``                Sequence Number Field
  12         96   ``ah.icv``                Integrity Check Value (ICV)
======= ========= ======================= ===================================

.. [*] https://en.wikipedia.org/wiki/IPsec

"""
from typing import TYPE_CHECKING, overload

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.ah import AH as Data_AH
from pcapkit.protocols.internet.ipsec import IPsec
from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
from pcapkit.protocols.schema.internet.ah import AH as Schema_AH
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['AH']


class AH(IPsec[Data_AH, Schema_AH], IPv6_Ext[Data_AH, Schema_AH],
         schema=Schema_AH, data=Data_AH):
    """This class implements Authentication Header.

    Double-inherited (GitHub issue :issue:`917`): ``AH`` is both a member of the
    IPsec family and an IPv6 extension header. IANA's *IPv6 Extension Header
    Types* registry lists it at 51 (:rfc:`4302#section-3.1.1` has it appear
    after the hop-by-hop, routing and fragmentation extension headers in the
    IPv6 header chain), and
    :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` agrees. The
    same section places it after the IP header and before the next-layer
    protocol under IPv4, so it also travels directly as an IPv4 payload, which
    is what qualifies it for a base besides
    :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`.
    :class:`~pcapkit.protocols.internet.ipsec.IPsec` comes first so that its
    :meth:`~pcapkit.protocols.internet.ipsec.IPsec.id` takes precedence.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Authentication Header"]':
        """Name of corresponding protocol."""
        return 'Authentication Header'

    @property
    def alias(self) -> 'Literal["AH"]':
        """Acronym of corresponding protocol.

        Spelled out rather than left to
        :attr:`ProtocolBase.alias <pcapkit.protocols.protocol.ProtocolBase.alias>`'s
        class-name default, because
        :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` sits between
        this class and that default in the MRO and carries its own
        ``'IPv6-Ext'`` (GitHub issue :issue:`917`). Inheriting it would rename
        this header in every :class:`~pcapkit.corekit.protochain.ProtoChain`
        string and in :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`'s packet
        dict key.

        """
        return 'AH'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'ProtocolBase | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return super().payload

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

    def read(self, length: 'Optional[int]' = None, *, version: 'Literal[4, 6]' = 4,  # pylint: disable=arguments-differ
             extension: bool = False, **kwargs: 'Any') -> 'Data_AH':  # pylint: disable=unused-argument
        """Read Authentication Header.

        Structure of AH header [:rfc:`4302`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Next Header   |  Payload Len  |          RESERVED             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Security Parameters Index (SPI)               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Sequence Number Field                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                Integrity Check Value-ICV (variable)           |
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        ah = Data_AH(
            next=schema.next,
            length=(schema.len + 2) * 4,
            reserved=schema.reserved,
            spi=schema.spi,
            seq=schema.seq,
            icv=schema.icv,
        )

        if extension:
            return ah
        return self._decode_next_layer(ah, schema.next, length - ah.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             reserved: 'int' = 0,
             spi: 'int' = 0,
             seq: 'int' = 0,
             icv: 'bytes' = b'',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_AH':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            next_default: Default value of next header type.
            next_namespace: Namespace of next header type.
            next_reversed: If the namespace is reversed.
            reserved: Reserved field; zero on send per :rfc:`4302#section-2.3`,
                but written as given so that a parsed header rebuilds unchanged.
            spi: Security Parameters Index.
            seq: Sequence Number Field.
            icv: Integrity Check Value-ICV.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_value = self._make_index(next, next_default, namespace=next_namespace,
                                      reversed=next_reversed, pack=False)
        length = (len(icv) + 12) // 4 - 2

        return Schema_AH(
            next=next_value,  # type: ignore[arg-type]
            len=length,
            reserved=reserved,
            spi=spi,
            seq=seq,
            icv=icv,
            payload=payload,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["AH"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('AH',)

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = ..., extension: 'bool' = ...,
                      **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = 4, extension: 'bool' = False,
                      **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`self.make <AH.make>`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, version=version, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[20]':
        """Return an estimated length for the object."""
        return 20

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.AH  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_AH') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'reserved': data.reserved,
            'spi': data.spi,
            'seq': data.seq,
            'icv': data.icv,
            'payload': cls._make_payload(data),
        }
