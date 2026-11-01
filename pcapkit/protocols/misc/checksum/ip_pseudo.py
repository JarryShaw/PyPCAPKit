# -*- coding: utf-8 -*-
"""IP Pseudo-Header
======================

.. module:: pcapkit.protocols.misc.checksum.ip_pseudo

:mod:`pcapkit.protocols.misc.checksum.ip_pseudo` contains
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo` only,
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

from pcapkit.const.ipv4.option_number import OptionNumber as Enum_IPv4Option
from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import parse_ip_address
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.misc.checksum.ip_pseudo import IP_Pseudo as Data_IP_Pseudo
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6 import IPV6_HEADER_LEN, IPv6
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.internet.ipv6 import IP_MAX_LENGTH, jumbo_payload_length
from pcapkit.protocols.schema.misc.checksum.ip_pseudo import IPV4_PSEUDO_LEN, IPV6_PSEUDO_LEN
from pcapkit.protocols.schema.misc.checksum.ip_pseudo import IP_Pseudo as Schema_IP_Pseudo
from pcapkit.utilities.exceptions import FieldValueError, ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

__all__ = ['IP_Pseudo']

#: Extension headers that end the chain, as the upper layer: the Mobility Header
#: (:rfc:`6275#section-6.1.1`) and HIP (:rfc:`7401#section-5.1.1`).
_TERMINAL_HEADERS = (Enum_ExtensionHeader.Mobility_Header, Enum_ExtensionHeader.HIP)


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
        return IPV6_PSEUDO_LEN if self._is_ipv6(self._info.src) else IPV4_PSEUDO_LEN  # type: ignore[return-value]

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

        """
        schema = self.__header__

        version: 'Literal[4, 6]' = schema.src.version
        return Data_IP_Pseudo(
            version=version,
            src=schema.src,
            dst=schema.dst,
            protocol=Enum_TransType.get(schema.protocol),
            len=schema.ipv6_len if self._is_ipv6(schema.src) else schema.ipv4_len,
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

        Values not given are read from ``ip``. ``src`` is a Home Address option's
        address (:rfc:`6275#section-11.3.1`); ``dst`` is the final destination of a
        Routing header with segments left, or of a source route (:rfc:`791`) not
        yet exhausted; ``protocol`` and ``upper_length`` lie past the extension
        headers, a UDP upper layer giving its Length field (:rfc:`768`) and a
        jumbogram its Jumbo Payload Length (:rfc:`2675`). Values ``ip`` lacks are
        to be given: an unparsed Routing destination (:rfc:`8754`), a fragment's
        length, or an upper layer behind an unparsed header such as ESP.

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
            ProtocolError: If ``ip`` is neither IPv4 nor IPv6, a value is given
                by neither the arguments nor ``ip``, or a header of ``ip`` is
                malformed or not parsed.
            FieldValueError: If ``src`` or ``dst`` is not a valid address,
                they differ in IP version, or ``upper_length`` does not fit
                the layout's length field.

        """
        if ip is not None:
            if not isinstance(ip, (IPv4, IPv6)):
                raise ProtocolError(f'{self.alias}: unsupported enclosing layer '
                                    f'{type(ip).__name__}')
            if src is None:
                src = self._source(ip)
            if dst is None:
                dst = self._destination(ip)
            from_layer = protocol is None
            if from_layer:
                protocol = self._upper_protocol(ip)
            if upper_length is None:
                upper_length = self._upper_length(ip, from_layer=from_layer)

        if src is None or dst is None or protocol is None or upper_length is None:
            raise ProtocolError(f'{self.alias}: src, dst, protocol and upper_length '
                                'are required without ip')

        src_val = parse_ip_address(src, f'{self.alias}: source address')
        dst_val = parse_ip_address(dst, f'{self.alias}: destination address', src_val.version)
        is_v6 = self._is_ipv6(src_val)
        limit = 0xFFFFFFFF if is_v6 else IP_MAX_LENGTH
        if not 0 <= upper_length <= limit:
            raise FieldValueError(f'{self.alias}: upper-layer length {upper_length} '
                                  f'out of range 0 to {limit:#x}')
        if protocol_namespace is None:
            protocol_namespace = Enum_TransType
        proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,
                                 reversed=protocol_reversed, pack=False)

        # NOTE: Kept at the layout's width, so that a constructed data model
        # matches the parsed one.
        width = 3 if is_v6 else 1
        zero = zero[:width].ljust(width, b'\x00')

        if is_v6:
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

        Raises:
            ProtocolError: If the octets parsed are not ``length`` long, or
                not 12 (IPv4) or 40 (IPv6) long.

        See Also:
            For construction arguments, please refer to :meth:`make`.

        """
        if file is not None:
            file = file if isinstance(file, bytes) else file.read(length)  # type: ignore[arg-type]
            if length is None:
                length = len(file)
            if len(file) != length:
                raise ProtocolError(f'{self.alias}: length {length} disagrees with '
                                    f'{len(file)} octets')
            if length not in (IPV4_PSEUDO_LEN, IPV6_PSEUDO_LEN):
                raise ProtocolError(f'{self.alias}: invalid length {length}; '
                                    f'expected {IPV4_PSEUDO_LEN} or {IPV6_PSEUDO_LEN}')
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

    def _source(self, ip: 'IPv4 | IPv6') -> 'IPv4Address | IPv6Address':
        """Read the pseudo-header source address from an IP layer.

        Args:
            ip: IPv4 or IPv6 layer.

        Returns:
            The address of a Home Address option (:rfc:`6275#section-11.3.1`)
            if any, the source address otherwise.

        Raises:
            ProtocolError: If a Destination Options header is not parsed,
                however deep in the chain.

        """
        src = ip.info.src
        if isinstance(ip, IPv6):
            for header in ip.extension_headers.getlist(Enum_ExtensionHeader.IPv6_Opts):  # type: ignore[arg-type]
                options = header.info.get('options')
                if options is None:
                    raise ProtocolError(f'{self.alias}: Destination Options of {ip.alias} not '
                                        'parsed; give src')
                option = options.get(Enum_Option.Home_Address)
                if option is not None:
                    src = option.address

            # NOTE: A header the walk stopped on, at any depth, is unparsed too, as
            # a malformed one is (#2480), and may hold a Home Address option.
            if self._walk(ip)[0] == Enum_ExtensionHeader.IPv6_Opts:
                raise ProtocolError(f'{self.alias}: Destination Options of {ip.alias} not '
                                    'parsed; give src')
        return src

    @staticmethod
    def _walk(ip: 'IPv6') -> 'tuple[Enum_TransType, int]':
        """Walk the extension headers of an IPv6 layer up to its upper layer.

        A Mobility Header or HIP (:rfc:`6275#section-6.1.1`, :rfc:`7401#section-5.1.1`)
        is the upper layer itself, and an Encapsulating Security Payload
        (:rfc:`4303`) ends the walk, its upper layer being encrypted.

        Args:
            ip: IPv6 layer.

        Returns:
            The code the walk stopped on, and the octets of the headers ahead of
            it. The code is an extension header's if ``ip`` did not parse that
            header: a malformed one (:issue:`2480`), one past the header limit,
            or one not captured.

        """
        code, before = ip.info.next, 0
        for _, header in ip.extension_headers.items(multi=True):
            if code in _TERMINAL_HEADERS or code == Enum_TransType.ESP:
                break
            before += header.length
            code = header.info.next
        return code, before

    def _destination(self, ip: 'IPv4 | IPv6') -> 'IPv4Address | IPv6Address':
        """Read the pseudo-header destination address from an IP layer.

        Args:
            ip: IPv4 or IPv6 layer.

        Returns:
            The last address still to be visited of a source route
            (:rfc:`791`) not yet exhausted, or of a Routing header with
            segments left; the destination address otherwise.

        Raises:
            ProtocolError: If a source route or Routing header is not parsed,
                or a Routing header with segments left has no parsed last
                address.

        """
        dst = ip.info.dst
        if isinstance(ip, IPv4):
            # NOTE: The header holds the next hop while the route has addresses
            # left; once exhausted (RFC 791 section 3.1) it is the destination.
            options = ip.info.get('options')
            if options is None:
                return dst
            for code in (Enum_IPv4Option.LSR, Enum_IPv4Option.SSR):
                for option in options.getlist(code):
                    if option.remaining:
                        dst = option.remaining[-1]
            return dst
        for header in ip.extension_headers.getlist(Enum_ExtensionHeader.IPv6_Route):  # type: ignore[arg-type]
            route = header.info
            seg_left = route.get('seg_left')
            if seg_left is None or route.get('__short_read__') is not None:
                raise ProtocolError(f'{self.alias}: Routing header of {ip.alias} not parsed; give dst')
            if not seg_left:
                continue
            # NOTE: Type 2 carries one address, the source routes a tuple. A
            # truncated RPL address stays bytes; unparsed types carry none.
            final = route.get('ip')
            if isinstance(final, tuple) and final:
                final = final[-1]
            if not isinstance(final, ipaddress.IPv6Address):
                raise ProtocolError(f'{self.alias}: final destination of Routing type '
                                    f'{route.type} not parsed; give dst')
            dst = final

        # NOTE: A header the walk stopped on, at any depth, is unparsed too, as
        # a malformed one is (#2480), and may have segments left.
        if self._walk(ip)[0] == Enum_ExtensionHeader.IPv6_Route:
            raise ProtocolError(f'{self.alias}: Routing header of {ip.alias} not parsed; give dst')
        return dst

    def _upper_protocol(self, ip: 'IPv4 | IPv6') -> 'Enum_TransType':
        """Read the upper-layer protocol from an IP layer.

        Args:
            ip: IPv4 or IPv6 layer.

        Returns:
            The protocol past the extension headers.

        Raises:
            ProtocolError: If the walk ended at an unparsed header: none, or
                an IPv6 extension header that was not walked, as past the
                header limit, or a truncated Routing or Fragment header.

        """
        return self._upper(ip)[0]

    def _upper(self, ip: 'IPv4 | IPv6') -> 'tuple[Enum_TransType, int]':
        """Read the upper-layer protocol and the octets of the headers ahead of it.

        A Mobility Header or HIP (:rfc:`6275#section-6.1.1`, :rfc:`7401#section-5.1.1`)
        is the upper layer itself. An Authentication Header (:rfc:`4302#section-2.2`)
        is walked past, its Next Header naming the upper layer, as in IPv6.

        Args:
            ip: IPv4 or IPv6 layer.

        Returns:
            The protocol past the extension headers, and the octets of those
            headers ahead of it.

        Raises:
            ProtocolError: If the walk ended at an unparsed header: none, an
                IPv6 extension header that was not walked, an Authentication
                Header cut short or in a non-first IPv4 fragment. An Encapsulating Security Payload
                (:rfc:`4303`) is never walked, its upper layer being encrypted.

        """
        if isinstance(ip, IPv4):
            code, before, offset = ip.info.protocol, 0, ip.info.hdr_len
            # NOTE: A non-first fragment's payload does not start with the AH its Protocol names.
            while code == Enum_TransType.AH and not ip.info.offset:
                # NOTE: Payload Len counts 32-bit words, less two (RFC 4302 section 2.2).
                octets = ip.data[offset:offset + 2]
                size = (octets[1] + 2) * 4 if len(octets) == 2 else 0
                if not size or offset + size > len(ip.data):
                    raise ProtocolError(f'{self.alias}: Authentication Header of {ip.alias} '
                                        'not parsed; give protocol and upper_length')
                code = Enum_TransType.get(ip.data[offset])
                before, offset = before + size, offset + size
            # NOTE: The upper layer of an ESP (RFC 4303) is encrypted, so it is never walked.
            unparsed = code in (Enum_TransType.AH, Enum_TransType.ESP)
        else:
            code, before = self._walk(ip)
            unparsed = code not in _TERMINAL_HEADERS and self._is_extension_header(code)

        # NOTE: What is missing is the protocol and the length, even where an
        # unparsed header also hides an address (#2513).
        if code is None or unparsed:
            raise ProtocolError(f'{self.alias}: upper layer of {ip.alias} not parsed; '
                                'give protocol and upper_length')
        return code, before

    @staticmethod
    def _is_ipv6(address: 'IPv4Address | IPv6Address') -> 'bool':
        """Tell whether ``address`` selects the IPv6 layout."""
        return isinstance(address, ipaddress.IPv6Address)

    @staticmethod
    def _is_extension_header(code: 'int') -> 'bool':
        """Tell whether ``code`` is an IPv6 extension header number."""
        try:
            Enum_ExtensionHeader(code)
        except ValueError:
            return False
        return True

    def _upper_length(self, ip: 'IPv4 | IPv6', *, from_layer: 'bool' = True) -> 'int':
        """Read the upper-layer packet length from an IP layer.

        Args:
            ip: IPv4 or IPv6 layer.
            from_layer: Whether the upper layer is the one ``ip`` carries,
                rather than one given by the caller.

        Returns:
            The Length field of a UDP header that is present, else the length
            past the IP header and extension headers.

        Raises:
            ProtocolError: If ``ip`` is a fragment, ends at an unparsed header,
                or has a zero Payload Length and no Jumbo Payload option.

        """
        if isinstance(ip, IPv4):
            info4 = ip.info
            if info4.offset or info4.flags.mf:
                raise ProtocolError(f'{self.alias}: {ip.alias} fragment; give upper_length')
            protocol, before = self._upper(ip)
            return self._udp_length(ip, protocol, info4.hdr_len + before,
                                    info4.len - info4.hdr_len - before, from_layer)

        protocol, before = self._upper(ip)
        info = ip.info
        for frag in ip.extension_headers.getlist(Enum_ExtensionHeader.IPv6_Frag):  # type: ignore[arg-type]
            if frag.info.offset or frag.info.mf:
                raise ProtocolError(f'{self.alias}: {ip.alias} fragment; give upper_length')

        extent = info.payload
        if not extent:
            jumbo = jumbo_payload_length(info.next, ip.data[IPV6_HEADER_LEN:])
            if jumbo is None:
                raise ProtocolError(f'{self.alias}: Payload Length 0 and no Jumbo Payload '
                                    'option; give upper_length')
            extent = jumbo
        # NOTE: ``info.hdr_len`` ends at the first Fragment header, so headers
        # after it are not counted; the fixed header plus ``before`` is the offset.
        return self._udp_length(ip, protocol, IPV6_HEADER_LEN + before, extent - before, from_layer)

    def _udp_length(self, ip: 'IPv4 | IPv6', protocol: 'int', hdr_len: 'int', length: 'int',
                    from_layer: 'bool') -> 'int':
        """Prefer the Length field of a UDP header to the length from the IP layer.

        Args:
            ip: IPv4 or IPv6 layer.
            protocol: Upper-layer protocol.
            hdr_len: Length of the IP header and extension headers.
            length: Length from the IP layer.
            from_layer: Whether the upper layer is the one ``ip`` carries.

        Returns:
            The UDP Length field (:rfc:`768`) if the upper layer is UDP and its
            header is present with a non-zero field, ``length`` otherwise.

        """
        if not from_layer or protocol != Enum_TransType.UDP:
            return length
        # NOTE: Octets 4 and 5 of the UDP header are its Length field. A zero
        # field is a jumbogram's, so the IP layer's length stands.
        start = hdr_len + 4
        octets = ip.data[start:start + 2]
        if len(octets) < 2:
            return length
        return int.from_bytes(octets, 'big') or length
