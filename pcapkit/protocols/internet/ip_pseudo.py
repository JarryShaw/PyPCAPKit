# -*- coding: utf-8 -*-
"""IP Pseudo-Header
======================

.. module:: pcapkit.protocols.internet.ip_pseudo

:mod:`pcapkit.protocols.internet.ip_pseudo` contains
:class:`~pcapkit.protocols.internet.ip_pseudo.IP_Pseudo` only,
which implements the pseudo-header of the IP protocol family
that the upper-layer checksums cover, whose structure is
described as below:

IPv4 (:rfc:`793#section-3.1`, :rfc:`768`):

======= ========= ========================= ===============================
Octets      Bits        Name                    Description
======= ========= ========================= ===============================
  0           0   ``ip_pseudo.src``           Source Address
  4          32   ``ip_pseudo.dst``           Destination Address
  8          64   ``ip_pseudo.zero``          Reserved
  9          72   ``ip_pseudo.protocol``      Protocol
  10         80   ``ip_pseudo.len``           Upper-Layer Packet Length
======= ========= ========================= ===============================

IPv6 (:rfc:`8200#section-8.1`):

======= ========= ========================= ===============================
Octets      Bits        Name                    Description
======= ========= ========================= ===============================
  0           0   ``ip_pseudo.src``           Source Address
  16        128   ``ip_pseudo.dst``           Destination Address
  32        256   ``ip_pseudo.len``           Upper-Layer Packet Length
  36        288   ``ip_pseudo.zero``          Reserved
  39        312   ``ip_pseudo.protocol``      Next Header
======= ========= ========================= ===============================

"""
import ipaddress
from typing import TYPE_CHECKING, overload

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import parse_ip_address
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.ip_pseudo import IP_Pseudo as Data_IP_Pseudo
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6 import IPV6_HEADER_LEN, IPv6
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.internet.ip_pseudo import IPV4_PSEUDO_LEN, IPV6_PSEUDO_LEN
from pcapkit.protocols.schema.internet.ip_pseudo import IP_Pseudo as Schema_IP_Pseudo
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

__all__ = ['IP_Pseudo']


class IP_Pseudo(ProtocolBase[Data_IP_Pseudo, Schema_IP_Pseudo],
                schema=Schema_IP_Pseudo, data=Data_IP_Pseudo):
    """This class implements the IP pseudo-header.

    It is not a layer on the wire: it is built from the enclosing
    :class:`~pcapkit.protocols.internet.ipv4.IPv4` or
    :class:`~pcapkit.protocols.internet.ipv6.IPv6` layer, or from explicit
    values, and its :attr:`data` is the octets an upper-layer checksum covers
    ahead of that layer's own. The layout follows the IP version of the source
    address, or the length of the octets parsed.

    .. versionadded:: 1.6.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["IP Pseudo-Header"]':
        """Name of current protocol."""
        return 'IP Pseudo-Header'

    @property
    def length(self) -> 'Literal[12, 40]':
        """Header length of current protocol."""
        return IPV6_PSEUDO_LEN if self._info.version == 6 else IPV4_PSEUDO_LEN  # type: ignore[return-value]

    @property
    def protocol(self) -> 'Enum_TransType':
        """Upper-layer protocol."""
        return self._info.protocol

    @property
    def version(self) -> 'Literal[4, 6]':
        """IP version of the enclosing layer."""
        return self._info.version

    @property
    def src(self) -> 'IPv4Address | IPv6Address':
        """Source address."""
        return self._info.src

    @property
    def dst(self) -> 'IPv4Address | IPv6Address':
        """Destination address."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IP_Pseudo':  # pylint: disable=unused-argument
        """Read IP pseudo-header.

        Structure of the IPv4 pseudo-header [:rfc:`793`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |           Source Address          |
           +--------+--------+--------+--------+
           |         Destination Address       |
           +--------+--------+--------+--------+
           |  zero  |  PTCL  |    TCP Length   |
           +--------+--------+--------+--------+

        Structure of the IPv6 pseudo-header [:rfc:`8200`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |                                   |
           +                                   +
           |                                   |
           +         Source Address            +
           |                                   |
           +                                   +
           |                                   |
           +--------+--------+--------+--------+
           |                                   |
           +                                   +
           |                                   |
           +       Destination Address         +
           |                                   |
           +                                   +
           |                                   |
           +--------+--------+--------+--------+
           |     Upper-Layer Packet Length     |
           +--------+--------+--------+--------+
           |          zero            |  Next  |
           +--------+--------+--------+--------+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the octets are not 12 (IPv4) or 40 (IPv6) long.

        """
        if length is None:
            length = len(self)
        if length not in (IPV4_PSEUDO_LEN, IPV6_PSEUDO_LEN):
            raise ProtocolError(f'{self.alias}: invalid length {length}; '
                                f'expected {IPV4_PSEUDO_LEN} or {IPV6_PSEUDO_LEN}')
        schema = self.__header__

        version: 'Literal[4, 6]' = schema.src.version
        return Data_IP_Pseudo(
            version=version,
            src=schema.src,
            dst=schema.dst,
            protocol=Enum_TransType.get(schema.protocol),
            len=schema.ipv6_len if version == 6 else schema.ipv4_len,
            zero=schema.zero,
        )

    def make(self,
             ip: 'Optional[IPv4 | IPv6]' = None,
             src: 'Optional[IPv4Address | IPv6Address | str | int | bytes]' = None,
             dst: 'Optional[IPv4Address | IPv6Address | str | int | bytes]' = None,
             protocol: 'Optional[Enum_TransType | StdlibEnum | AenumEnum | int | str]' = None,
             protocol_default: 'Optional[int]' = None,
             protocol_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             protocol_reversed: 'bool' = False,
             upper_length: 'Optional[int]' = None,
             zero: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_IP_Pseudo':
        """Make (construct) packet data.

        Values not given are taken from ``ip``. From an
        :class:`~pcapkit.protocols.internet.ipv6.IPv6` layer, ``dst`` is the
        final destination of a Routing header with segments left, and
        ``protocol`` and ``upper_length`` are those past the extension headers,
        as :rfc:`8200#section-8.1` specifies.

        Args:
            ip: Parsed or constructed IP layer enclosing the upper layer.
            src: Source address; its IP version selects the layout.
            dst: Destination address, of the same IP version as ``src``.
            protocol: Upper-layer protocol number.
            protocol_default: Default value of ``protocol``.
            protocol_namespace: Namespace of ``protocol``;
                :class:`~pcapkit.const.reg.transtype.TransType` by default.
            protocol_reversed: Whether to reverse the namespace of ``protocol``.
            upper_length: Upper-layer packet length, header included.
            zero: Reserved octets, truncated or zero-filled to the layout's width.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``ip`` is neither IPv4 nor IPv6, or a value is
                given by neither the arguments nor ``ip``.
            FieldValueError: If ``src`` or ``dst`` is not a valid address, or
                they differ in IP version.

        """
        if ip is not None:
            if not isinstance(ip, (IPv4, IPv6)):
                raise ProtocolError(f'{self.alias}: unsupported enclosing layer '
                                    f'{type(ip).__name__}')
            ip_src, ip_dst, ip_proto, ip_len = self._from_ip(ip)
            src = ip_src if src is None else src
            dst = ip_dst if dst is None else dst
            protocol = ip_proto if protocol is None else protocol
            upper_length = ip_len if upper_length is None else upper_length

        if src is None or dst is None or protocol is None or upper_length is None:
            raise ProtocolError(f'{self.alias}: src, dst, protocol and upper_length '
                                'are required without ip')

        src_val = parse_ip_address(src, f'{self.alias}: source address')
        dst_val = parse_ip_address(dst, f'{self.alias}: destination address', src_val.version)
        if protocol_namespace is None:
            protocol_namespace = Enum_TransType
        proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,
                                 reversed=protocol_reversed, pack=False)

        # NOTE: Kept at the layout's width, so that a constructed data model
        # matches the parsed one.
        width = 3 if src_val.version == 6 else 1
        zero = zero[:width].ljust(width, b'\x00')

        if src_val.version == 6:
            return Schema_IP_Pseudo(
                src=src_val,
                dst=dst_val,
                ipv6_len=upper_length,
                zero=zero,
                protocol=proto,
            )
        return Schema_IP_Pseudo(
            src=src_val,
            dst=dst_val,
            zero=zero,
            protocol=proto,
            ipv4_len=upper_length,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction arguments, please refer to :meth:`make`.

        """
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

        #: pcapkit.protocols.misc.null.NoPayload: Next layer (no payload).
        self._next = NoPayload()
        #: pcapkit.corekit.protochain.ProtoChain: Protocol chain from current layer.
        self._protos = ProtoChain(self.__class__, self.alias)

    def __length_hint__(self) -> 'Literal[12]':
        """Return an estimated length for the object."""
        return IPV4_PSEUDO_LEN  # type: ignore[return-value]

    @classmethod
    def __index__(cls) -> 'NoReturn':
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IP_Pseudo') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'src': data.src,
            'dst': data.dst,
            'protocol': data.protocol,
            'upper_length': data.len,
            'zero': data.zero,
        }

    @staticmethod
    def _from_ip(ip: 'IPv4 | IPv6') -> 'tuple[IPv4Address | IPv6Address, IPv4Address | IPv6Address, Enum_TransType, int]':  # pylint: disable=line-too-long
        """Read the pseudo-header values from an IP layer.

        Args:
            ip: IPv4 or IPv6 layer.

        Returns:
            Source address, destination address, upper-layer protocol and
            upper-layer packet length.

        """
        if isinstance(ip, IPv4):
            info4 = ip.info
            return info4.src, info4.dst, info4.protocol, info4.len - info4.hdr_len

        info = ip.info
        dst = info.dst
        for header in ip.extension_headers.getlist(Enum_ExtensionHeader.IPv6_Route):  # type: ignore[arg-type]
            route = header.info
            # NOTE: Type 2 carries one address, the source routes a tuple; an
            # RPL address left compressed (bytes) is not a final destination.
            final = route.get('ip')
            if isinstance(final, tuple) and final:
                final = final[-1]
            if route.seg_left and isinstance(final, ipaddress.IPv6Address):
                dst = final
        return info.src, dst, info.protocol, info.payload - (info.hdr_len - IPV6_HEADER_LEN)
