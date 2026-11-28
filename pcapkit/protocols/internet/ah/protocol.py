# -*- coding: utf-8 -*-
"""AH - Authentication Header
================================

.. module:: pcapkit.protocols.internet.ah.protocol

:mod:`pcapkit.protocols.internet.ah.protocol` contains
:class:`~pcapkit.protocols.internet.ah.protocol.AH` only,
which implements the extractor for Authentication
Header (AH) [*]_, whose structure is described
as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``ah.next``               Next Header
  1           8   ``ah.length``             Payload Length
  2          16   ``ah.reserved``           Reserved (must be zero)
  4          32   ``ah.spi``                Security Parameters Index (SPI)
  8          64   ``ah.seq``                Sequence Number Field
  12         96   ``ah.icv``                Integrity Check Value (ICV)
======= ========= ======================= ===================================

.. [*] https://en.wikipedia.org/wiki/IPsec

"""
from typing import TYPE_CHECKING, overload

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.const.ip_header import AH_HEADER_LEN
from pcapkit.corekit.schema.short_read import cut_on_its_own
from pcapkit.protocols.internet.ah.data import AH as Data_AH
from pcapkit.protocols.internet.ah.schema import AH as Schema_AH
from pcapkit.protocols.internet.ipsec.protocol import IPsec
from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext
from pcapkit.protocols.misc.no_payload.protocol import NoPayload
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import IO, Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['AH']


class AH(IPsec[Data_AH, Schema_AH], IPv6_Ext[Data_AH, Schema_AH],
         schema=Schema_AH, data=Data_AH):
    """This class implements Authentication Header.

    Double-inherited (:issue:`917`): :class:`~pcapkit.protocols.internet.ah.protocol.AH` is both a member
    of the IPsec family and an IPv6 extension header. IANA's *IPv6 Extension Header
    Types* registry lists it at 51 (:rfc:`4302#section-3.1.1` has it appear
    after the hop-by-hop, routing and fragmentation extension headers in the
    IPv6 header chain), and
    :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` agrees. The
    same section places it after the IP header and before the next-layer
    protocol under IPv4, so it also travels directly as an IPv4 payload, which
    is what qualifies it for a base besides
    :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`.
    :class:`~pcapkit.protocols.internet.ipsec.protocol.IPsec` comes first so that its
    :meth:`~pcapkit.protocols.internet.ipsec.protocol.IPsec.id` takes precedence.

    .. versionchanged:: 1.5.0

       A rebuild writes the reserved field back as captured rather than as
       zero (:issue:`1327`).

    .. versionchanged:: 1.6.0

       ``next`` of :meth:`make` takes a member or an :class:`int` code,
       resolved with the enumeration's ``get``; a name, a :obj:`bool`, or a
       code that does not fit in one octet raises
       :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than
       resolving against an enumeration inferred from the caller's frame or
       writing a different value (:issue:`2594`).

    .. versionremoved:: 1.6.0

       The ``next_default``, ``next_namespace`` and ``next_reversed``
       arguments of :meth:`make`; resolve a name with
       :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

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
        :attr:`Protocol.alias <pcapkit.protocols.protocol.Protocol.alias>`'s
        class-name default, because
        :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext` sits between
        this class and that default in the MRO and carries its own
        ``'IPv6-Ext'`` (:issue:`917`). Inheriting it would rename
        this header in every :class:`~pcapkit.corekit.protochain.ProtoChain`
        string and in :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.protocol.IPv6._decode_next_layer>`'s packet
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

        Raises:
            ProtocolError: If Payload Length describes fewer octets than the
                fixed fields (:rfc:`4302#section-2.2`). Parsed on its own, one
                the cut left as zero is the short read's (:issue:`2880`).

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        # NOTE: A Payload Length read below the fixed fields is refused as a whole header's is;
        # on its own, one the cut left as zero is the short read's (#2880).
        if (schema.len + 2) * 4 < AH_HEADER_LEN and not cut_on_its_own(schema, 'len'):
            raise ProtocolError(f'{self.alias}: invalid payload length: {schema.len}')

        ah = Data_AH(
            next=schema.next,
            length=(schema.len + 2) * 4,
            reserved=schema.reserved,
            spi=schema.spi,
            seq=schema.seq,
            icv=schema.icv,
        )

        if extension:
            # NOTE: As an IPv6 extension header the upper layer belongs to the enclosing
            # IPv6 header, so hold NoPayload here so that membership does not raise (#2484).
            self._next = NoPayload.from_fields()  # pylint: disable=attribute-defined-outside-init
            return ah
        # NOTE: The payload is the rest of the parent's, so a frame's cut the
        # parent handed on is handed on in turn (#2689).
        return self._decode_next_layer(ah, schema.next, length - ah.length, declared=False)

    def make(self, *,
             next: 'Enum_TransType | int' = Enum_TransType.UDP,
             reserved: 'int' = 0,
             spi: 'int' = 0,
             seq: 'int' = 0,
             icv: 'bytes' = b'',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             payload_length: 'Optional[int]' = None,
             version: 'Literal[4, 6]' = 4,
             extension: 'bool' = False,
             **kwargs: 'Any') -> 'Schema_AH':
        """Make (construct) packet data.

        Without ``payload_length``, the ICV field is ``icv`` and the fewest
        zero octets that make the header a multiple of 32 bits under IPv4 or
        64 bits under IPv6 (:rfc:`4302#section-2.6`);
        :rfc:`4302#section-3.3.3.2.1` leaves the padding's content to the
        sender. Payload Length counts the padding (:rfc:`4302#section-2.2`),
        and a parse reads it back as part of ``icv``.

        Args:
            next: Next header type.
            reserved: Reserved field; zero on send per :rfc:`4302#section-2.3`,
                but written as given so that a parsed header rebuilds unchanged.
            spi: Security Parameters Index.
            seq: Sequence Number Field.
            icv: Integrity Check Value (ICV), with any padding already in it
                kept as given.
            payload: Payload of current instance.
            payload_length: Payload Length, in 32-bit words minus 2; computed
                from the padded ICV when omitted. When given, it must describe
                ``icv`` exactly, and no padding is added, so that
                :meth:`_make_data` rebuilds a parsed header as captured,
                aligned or not.
            version: Version of the IP header carrying this one, which sets
                the alignment :rfc:`4302#section-3.3.3.2.1` pads the ICV to.
            extension: If the header is an IPv6 extension header, aligned for
                IPv6 whatever ``version`` says, since :meth:`__post_init__`
                always passes ``version`` its default of ``4``.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``next`` is a name, a :obj:`bool`, or a member
                or code that does not fit in one octet, ``version`` is neither
                ``4`` nor ``6``, the padded ICV is too long for Payload Length
                to count, or ``payload_length`` does not fit in one octet or
                does not describe ``icv`` exactly.

        .. versionchanged:: 1.5.0

           Takes ``reserved`` ahead of ``spi`` (:issue:`1327`), which shifts
           every later positional argument.

        .. versionchanged:: 1.7.0

           Pads ``icv`` to the alignment ``version`` and ``extension`` set,
           where it cut the octets past a multiple of 32 bits, and refuses an
           ICV too long for Payload Length, where it wrapped the field; takes
           ``payload_length`` (:issue:`2886`).

        """
        next_value = self._make_index(next, Enum_TransType, bits=8, name='next header')
        if version not in (4, 6):
            raise ProtocolError(f'{self.alias}: invalid version: must be 4 or 6, not {version!r}')

        if payload_length is None:
            # NOTE: RFC 4302 s2.6 pads the header to 4 octets under IPv4 and 8 under IPv6.
            align = 8 if extension or version == 6 else 4
            field = icv + bytes(-(AH_HEADER_LEN + len(icv)) % align)
            length = (AH_HEADER_LEN + len(field)) // 4 - 2
            if length > 0xff:
                most = (0xff + 2) * 4 // align * align - AH_HEADER_LEN
                raise ProtocolError(f'{self.alias}: invalid ICV length: must be at most {most} octets '
                                    f'under IPv{6 if align == 8 else 4}, not {len(icv)}')
        else:
            # NOTE: RFC 4302 s3.3.3.2.1 prohibits padding past the minimum, so a given
            # length adds none: it describes the field ``icv`` already is.
            length = self._make_uint(payload_length, bits=8, name='payload length')
            if (length + 2) * 4 - AH_HEADER_LEN != len(icv):
                raise ProtocolError(f'{self.alias}: invalid payload length: must describe the '
                                    f'{len(icv)}-octet ICV exactly, not {length}')
            field = icv

        return Schema_AH(
            next=next_value,
            len=length,
            reserved=reserved,
            spi=spi,
            seq=seq,
            icv=field,
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
            For construction arguments, please refer to :meth:`self.make <AH.make>`.

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
        # NOTE: A Payload Length the cut left as zero is the short read's, not one read (#2880),
        # so ``make`` computes one, and the cut back drops it with the octets past the capture.
        record = data.get('__short_read__')
        cut = record is not None and record[0] in ('next', 'len')
        return {
            'next': data.next,
            'reserved': data.reserved,
            'spi': data.spi,
            'seq': data.seq,
            'icv': data.icv,
            'payload': cls._make_payload(data),
            # NOTE: Written as captured, so that a header not aligned for the IP version
            # carrying it is not padded on a rebuild (#2886).
            'payload_length': None if cut else data.length // 4 - 2,
        }
