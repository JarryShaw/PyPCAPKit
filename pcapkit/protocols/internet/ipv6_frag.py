# -*- coding: utf-8 -*-
"""IPv6-Frag - Fragment Header for IPv6
==========================================

.. module:: pcapkit.protocols.internet.ipv6_frag

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

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.ipv6_frag import IPv6_Frag as Data_IPv6_Frag
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.ipv6_frag import IPv6_Frag as Schema_IPv6_Frag
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IPv6_Frag']


class IPv6_Frag(Internet[Data_IPv6_Frag, Schema_IPv6_Frag],
                schema=Schema_IPv6_Frag, data=Data_IPv6_Frag):
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
             **kwargs: 'Any') -> 'Data_IPv6_Frag':  # pylint: disable=unused-argument
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
        schema = self.__header__

        ipv6_frag = Data_IPv6_Frag(
            next=schema.next,
            offset=schema.flags['offset'],
            mf=bool(schema.flags['mf']),
            id=schema.id,
        )

        if extension:
            return ipv6_frag
        return self._decode_next_layer(ipv6_frag, schema.next, length - self.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             offset: 'int' = 0,
             mf: 'bool' = False,
             id: 'int' = 0,
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6_Frag':
        """Make (construct) packet data.

        Args:
            next: Next header.
            next_default: Default value of next header.
            next_namespace: Namespace of next header.
            next_reversed: If the namespace of next header is reversed.
            offset: Fragment offset.
            mf: More fragments flag.
            id: Identification.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,
                                    reversed=next_reversed, pack=False)

        return Schema_IPv6_Frag(
            next=next_val,  # type: ignore[arg-type]
            flags={
                'offset': offset,
                'mf': mf,
            },
            id=id,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`self.make <IPv6_Frag.make>`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object."""
        return 8

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPv6_Frag  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv6_Frag') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'offset': data.offset,
            'mf': data.mf,
            'id': data.id,
            'payload': cls._make_payload(data),
        }
