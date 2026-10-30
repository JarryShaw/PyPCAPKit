# -*- coding: utf-8 -*-
"""IPv6 - Internet Protocol version 6
========================================

.. module:: pcapkit.protocols.internet.ipv6

:mod:`pcapkit.protocols.internet.ipv6` contains
:class:`~pcapkit.protocols.internet.ipv6.IPv6` only,
which implements the extractor for Internet Protocol
version 6 (IPv6) [*]_, whose structure is described
as below:

======= ========= ===================== =======================================
Octets      Bits        Name                    Description
======= ========= ===================== =======================================
  0           0   ``ipv6.version``            Version (``6``)
  0           4   ``ipv6.class``              Traffic Class
  1          12   ``ipv6.label``              Flow Label
  4          32   ``ipv6.payload``            Payload Length (header excluded)
  6          48   ``ipv6.next``               Next Header
  7          56   ``ipv6.limit``              Hop Limit
  8          64   ``ipv6.src``                Source Address
  24        192   ``ipv6.dst``                Destination Address
======= ========= ===================== =======================================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet

"""
import ipaddress
from typing import TYPE_CHECKING

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.protocol import _frame_depth
from pcapkit.protocols.schema.internet.ipv6 import IP_MAX_LENGTH
from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length, jumbogram_error
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address
    from typing import Any, Mapping, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IPv6']

#: Length of the fixed IPv6 header, i.e. the offset of the first extension
#: header, :rfc:`8200#section-3`. The one home of this value (:issue:`1739`); it
#: is fixed by the RFC, so it is never configurable.
#:
#: .. versionadded:: 1.5.0
IPV6_HEADER_LEN = 40

#: Offset of the Next Header field within the fixed IPv6 header,
#: :rfc:`8200#section-3`. The one home of this value (:issue:`1739`).
#:
#: .. versionadded:: 1.5.0
IPV6_NEXT_HEADER_OFFSET = 6


class IPv6(IP[Data_IPv6, Schema_IPv6],
           schema=Schema_IPv6, data=Data_IPv6):
    """This class implements Internet Protocol version 6.

    .. versionchanged:: 1.5.0

       * A Shim6 header, which has no dedicated parser, and an extension
         header other than ESP whose dedicated parser raises are parsed by
         :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`, so the rest
         of the chain is still walked (:issue:`891`).
       * A rebuild from
         :meth:`~pcapkit.protocols.internet.internet.Internet.from_data`
         keeps the Payload Length a truncated capture declares
         (:issue:`1155`), and the octets past it as
         :attr:`~pcapkit.protocols.schema.internet.ipv6.IPv6.trailer`
         (:issue:`1209`).
       * Next Header codes 253 and 254 are parsed and rebuilt once
         (:issue:`1231`), and a cut extension header chain rebuilds byte for
         byte (:issue:`1471`, :issue:`1473`).

    .. versionchanged:: 1.6.0

       An extension header whose dedicated parser raises is the upper layer,
       parsed once as :class:`~pcapkit.protocols.misc.raw.Raw`, and the chain
       walk stops there, as :rfc:`8200#section-4` has a node discard such a
       packet (:issue:`2477`).

    .. versionremoved:: 1.6.0

       ``__generic_ext_codes__``, the extension headers whose dedicated parser
       raising fell back to
       :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` (:issue:`2477`).

    """

    #: The layer a header-walk stopped on, returned unparsed as the upper layer.
    _walk_upper = None  # type: Optional[ProtocolBase]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Protocol version 6"]':
        """Name of corresponding protocol."""
        return 'Internet Protocol version 6'

    @property
    def length(self) -> 'Literal[40]':
        """Header length of corresponding protocol."""
        return IPV6_HEADER_LEN  # type: ignore[return-value]

    @property
    def protocol(self) -> 'Enum_TransType':
        """Name of next layer protocol."""
        return self._info.protocol

    # source IP address
    @property
    def src(self) -> 'IPv6Address':
        """Source IP address."""
        return self._info.src

    # destination IP address
    @property
    def dst(self) -> 'IPv6Address':
        """Destination IP address."""
        return self._info.dst

    @property
    def extension_headers(self) -> 'OrderedMultiDict[Enum_ExtensionHeader, ProtocolBase]':
        """IPv6 extension header records."""
        return self._exthdr

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *,
             __packet__: 'Optional[dict[str, Any]]' = None, **kwargs: 'Any') -> 'Data_IPv6':  # pylint: disable=unused-argument
        """Read Internet Protocol version 6 (IPv6).

        Structure of IPv6 header [:rfc:`8200`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |Version| Traffic Class |           Flow Label                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Payload Length        |  Next Header  |   Hop Limit   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                         Source Address                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                      Destination Address                      +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            __packet__: Optional packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the version is not 6, or if the packet is one of
                the errors :rfc:`2675#section-3` has a receiver detect (see
                :func:`~pcapkit.protocols.schema.internet.ipv6.jumbogram_error`).

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        # NOTE: This class reads IPv6 only, as :meth:`IPv4.read
        # <pcapkit.protocols.internet.ipv4.IPv4.read>` reads IPv4 only; telling
        # the two apart by the Version is left to the dispatchers (#1680).
        if schema.hextet['version'] != 6:
            raise ProtocolError(f"[IPv6] invalid version: {schema.hextet['version']}")

        # NOTE: A receiver treats each of these as an error (#1687), so
        # the frame stops here, see :meth:`IPv4.read
        # <pcapkit.protocols.internet.ipv4.IPv4.read>`. A Fragment header beside
        # the Jumbo Payload option is caught on the walk, see
        # :meth:`_decode_next_layer`.
        rest = schema.get_payload() + schema.trailer
        error = jumbogram_error(schema.length, schema.next, rest)
        if error is not None:
            raise ProtocolError(f'{self.alias}: {error}')

        ipv6 = Data_IPv6.from_dict({
            'version': schema.hextet['version'],
            'class': schema.hextet['class'],
            'label': schema.hextet['label'],
            'payload': schema.length,
            'next': schema.next,
            'limit': schema.limit,
            'src': schema.src,
            'dst': schema.dst,
        })  # type: Data_IPv6

        # NOTE: Octets captured past the Payload Length are kept as captured,
        # see :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>`
        # (#1209).
        if schema.trailer:
            ipv6.__update__({
                'trailer': schema.trailer,
            })

        # NOTE: A jumbogram's extent is its Jumbo Payload Length, not the zero
        # Payload Length, see :meth:`Schema_IPv6.post_process
        # <pcapkit.protocols.schema.internet.ipv6.IPv6.post_process>`
        # (#1434); the check above leaves a zero one beside it.
        jumbo = jumbo_payload_length(schema.next, rest)
        extent = schema.length if jumbo is None else jumbo

        # update packet info
        if __packet__ is None:
            __packet__ = {}
        __packet__.update({
            'src': ipv6.src,
            'dst': ipv6.dst,
        })

        return self._decode_next_layer(ipv6, schema.next, extent, packet=__packet__)  # pylint: disable=no-member

    def make(self,
             traffic_class: 'int' = 0,
             flow_label: 'int' = 0,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             hop_limit: 'int' = 64,  # reasonable default
             src: 'IPv6Address | str | bytes | int' = '::1',
             dst: 'IPv6Address | str | bytes | int' = '::',
             payload_length: 'Optional[int]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6':
        """Make (construct) packet data.

        Args:
            traffic_class: Traffic class.
            flow_label: Flow label.
            next: Next header.
            next_default: Default value of next header.
            next_namespace: Namespace of next header.
            next_reversed: Whether to reverse the namespace of next header.
            hop_limit: Hop limit.
            src: Source IP address.
            dst: Destination IP address.
            payload_length: Length of the payload, extension headers included;
                computed from the payload when omitted, and zero (a jumbogram)
                if that exceeds 65,535 octets or the payload starts with a
                Hop-by-Hop Options header carrying a Jumbo Payload option.
            payload: Payload data.
            trailer: Octets after the packet, outside the Payload Length, such
                as link-layer padding; written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        .. versionchanged:: 1.5.0

           Takes ``payload_length`` ahead of ``payload`` (:issue:`1155`), which
           shifts a positional ``payload``.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,
                                    reversed=next_reversed, pack=False)

        # NOTE: An explicit ``payload_length`` is written as given, so that a
        # ``from_data`` rebuild of a capture truncated by snaplen keeps the
        # length the sender declared instead of the one that was recorded
        # (#1155). Computed from the octets at hand otherwise, which is
        # what a plain ``IPv6(payload=...)`` wants -- or zero for a payload too
        # long for the field, or one whose Hop-by-Hop Options header carries a
        # Jumbo Payload option, i.e. a jumbogram, whose length the caller gives
        # there (:rfc:`2675#section-2`); its Payload Length must be zero
        # (#1687).
        if payload_length is None:
            payload_length = len(payload)
            if payload_length > IP_MAX_LENGTH or jumbo_payload_length(next_val, bytes(payload)) is not None:
                payload_length = 0

        return Schema_IPv6(
            hextet={
                'version': 6,
                'class': traffic_class,
                'label': flow_label,
            },
            length=payload_length,
            next=next_val,  # type: ignore[arg-type]
            limit=hop_limit,
            src=src,
            dst=dst,
            payload=payload,
            trailer=trailer,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["IPv6"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('IPv6',)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[40]':
        """Return an estimated length for the object."""
        return IPV6_HEADER_LEN  # type: ignore[return-value]

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPv6  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv6') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        # NOTE: The chain is rebuilt from ``__exthdr__`` alone, which
        # :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
        # carries; without it, no extension header is rebuilt, and none is
        # guessed from the keys of ``data``, whose order is not part of the
        # contract of an :class:`~pcapkit.corekit.infoclass.Info` and differs
        # on PyPy (#2003).
        exthdr = data.get('__exthdr__')  # type: Optional[tuple[tuple[Type[ProtocolBase], Any], ...]] # pylint: disable=line-too-long
        chain = tuple(exthdr) if isinstance(exthdr, (tuple, list)) else ()
        upper = cls._make_payload(data)
        payload = upper  # type: bytes | ProtocolBase

        # NOTE: The extension headers sit between this header and the upper
        # layer payload, so they are rebuilt in wire order ahead of it.
        if chain:
            payload = b''.join(proto.from_data(info).data for proto, info in chain) + upper.data

        return {
            'traffic_class': data['class'],
            'flow_label': data.label,
            'next': data.next,
            'hop_limit': data.limit,
            'src': data.src,
            'dst': data.dst,
            # NOTE: ``data.payload`` is the parsed payload length, passed through
            # rather than left to ``make`` to recompute, so that a truncated
            # capture rebuilds with the length that was on the wire
            # (#1155).
            'payload_length': data.payload,
            'payload': payload,
            # NOTE: And the octets captured past the Payload Length (#1209).
            'trailer': data.get('trailer', b''),
        }

    @staticmethod
    def _exthdr_key(alias: 'str') -> 'str':
        """Key an extension header's info is written under in :class:`Data_IPv6`.

        Args:
            alias: :attr:`~pcapkit.protocols.protocol.Protocol.alias` of
                the extension header's parser.

        Returns:
            The key; :meth:`str.lstrip` strips a character *set*, which every
            parser's alias is chosen to suit.

        """
        return alias.lstrip('IPv6-').lower()

    @staticmethod
    def _is_first_fragment(info: 'Mapping[str, Any]') -> 'bool':
        """Whether a Fragment header's info is that of a first fragment.

        Args:
            info: info of a Fragment header, as parsed or from :meth:`Info.to_dict
                <pcapkit.corekit.infoclass.Info.to_dict>`

        Returns:
            :data:`True` at a Fragment Offset of zero.

        """
        return info.get('offset') == 0

    def _read_ip_hextet(self) -> 'tuple[int, int, int]':
        """Read the first four octets of IPv6.

        Returns:
            Parsed data of those four octets: version number, traffic class
            and flow label.

        """
        _htet = self._read_fileng(4).hex()
        _vers = int(_htet[0], base=16)      # version number (6)
        _tcls = int(_htet[1:3], base=16)    # traffic class
        _flow = int(_htet[3:], base=16)     # flow label

        return (_vers, _tcls, _flow)

    def _read_ip_addr(self) -> 'IPv6Address':
        """Read IP address.

        Returns:
            Parsed IP address.

        """
        return ipaddress.ip_address(self._read_fileng(16))  # type: ignore[return-value]

    def _decode_next_layer(self, ipv6: 'Data_IPv6', proto: 'Optional[int]' = None,  # type: ignore[override] # pylint: disable=arguments-differ,arguments-renamed
                           length: 'Optional[int]' = None, *, packet: 'Optional[dict[str, Any]]' = None) -> 'Data_IPv6':  # pylint: disable=arguments-differ
        """Decode next layer extractor.

        Arguments:
            ipv6: info buffer
            proto: next layer protocol index
            length: valid (*not padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Current protocol with next layer extracted.

        Raises:
            ProtocolError: If the walk reaches a Fragment header in a packet
                carrying a Jumbo Payload option, an error by
                :rfc:`2675#section-3` (:issue:`1687`).

        """
        #: Extension headers.
        self._exthdr = OrderedMultiDict()  # type: OrderedMultiDict[Enum_ExtensionHeader, ProtocolBase] # pylint: disable=attribute-defined-outside-init

        hdr_len = self.length       # header length
        raw_len = ipv6.payload if length is None else length  # payload length
        _protos = []                # type: list[ProtocolBase] # ProtoChain buffer
        _exthdr = []                # type: list[tuple[Type[ProtocolBase], Any]] # (parser class, info) per extension header
        split = None                # type: Optional[tuple[int, int]] # at first Fragment header
        opaque = False              # walk ended at a non-zero Fragment Offset
        depth = _frame_depth.get()  # layers of the frame up to this one

        # traverse if next header is an extension header
        payload = self.__header__.get_payload()
        while True:
            try:
                ex_proto = Enum_ExtensionHeader(proto)
            except ValueError:
                break

            # NOTE: At most :data:`EXTENSION_HEADER_LIMIT
            # <pcapkit.utilities.config.EXTENSION_HEADER_LIMIT>`
            # headers are walked, as at most that many are dissected after any
            # other layer. This header and the rest are then the upper layer,
            # which :meth:`_import_next_layer` keeps raw, with one warning
            # (#1604).
            if config.EXTENSION_HEADER_LIMIT != -1 and len(_protos) >= config.EXTENSION_HEADER_LIMIT:
                break

            # NOTE: Likewise past :data:`FRAME_LAYER_LIMIT
            # <pcapkit.utilities.config.FRAME_LAYER_LIMIT>` layers of the
            # frame (#1610), since each header walked is one of them.
            if config.FRAME_LAYER_LIMIT != -1 and depth + len(_protos) >= config.FRAME_LAYER_LIMIT:
                break

            # # directly break when No Next Header occurs
            # if proto.name == 'IPv6-NoNxt':
            #     proto = None
            #     break

            # make protocol name
            # NOTE: Counted after every header walked, as it would be were each
            # dissected by the one before it. ESP dissects its decrypted
            # payload even when walked, and those layers count on from here.
            token = _frame_depth.set(depth + len(_protos))
            try:
                next_ = self._import_next_layer(proto, packet=packet, version=6, extension=True,
                                                payload=payload)  # type: ignore[misc,call-arg]
            finally:
                _frame_depth.reset(token)
            info = next_.info

            # A layer with no ``next`` field cannot safely continue the walk.
            # This is a *structural* check, not a fixed set of codes: every
            # dedicated parser and
            # :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` carry
            # ``next`` (possibly :data:`None`, on an overrun) -- Shim6 has no
            # dedicated parser but is registered to ``IPv6_Ext`` directly --
            # while plain :class:`~pcapkit.protocols.misc.raw.Raw` does not.
            # That is what a code with no dedicated parser -- ``253``,
            # ``254``, or whatever IANA assigns next -- resolves to, and what
            # :func:`~pcapkit.corekit.decorators.beholder` makes of a header
            # whose dedicated parser raises, so a malformed header ends the
            # walk, as :rfc:`8200#section-4` has a node discard the packet
            # (#2477). Reading ``info.next`` on that would raise
            # ``AttributeError`` and let a further-out ``beholder`` degrade the
            # *whole* packet.
            #
            # Not recorded as an extension header, as it consumed nothing and
            # would be rebuilt twice. It is the upper layer instead, returned
            # unparsed by :meth:`_import_next_layer`, so its error is logged once.
            if not hasattr(info, 'next'):
                self._walk_upper = next_
                break

            # NOTE: Added through a :class:`MultiDict`, so a repeated header
            # keeps its predecessor's info rather than overwriting it, and
            # :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
            # writes every one of them (#1453).
            name = self._exthdr_key(next_.alias)
            ipv6.__update__(OrderedMultiDict([(name, info)]))

            # record protocol name
            # self._protos = ProtoChain(name, chain, alias)
            _protos.append(next_)
            _exthdr.append((type(next_), info))

            # update header & payload length
            hdr_len += next_.length  # type: ignore[assignment]
            raw_len -= next_.length

            # keep record of extension headers
            self._exthdr.add(ex_proto, next_)

            # update payload for the next header -- either the next extension
            # header, or the upper layer protocol should this be the last one;
            # this must happen before any exit from the loop, since the payload
            # is what gets handed to ``super()._decode_next_layer`` below
            payload = payload[next_.length:]

            proto = info.next

            # keep original data after fragment header
            if ex_proto == Enum_ExtensionHeader.IPv6_Frag:
                # NOTE: The first Fragment header splits the packet for
                # reassembly, so ``fragment``, ``hdr_len`` and ``raw_len`` keep
                # that split however far the walk goes on.
                if split is None:
                    # NOTE: Nor may a jumbogram carry one (#1687), so the
                    # frame stops here as for the errors :meth:`read` checks;
                    # past those, its Jumbo Payload option is in the payload.
                    error = jumbogram_error(ipv6.payload, ipv6.next, self.__header__.get_payload(), lambda: True)
                    if error is not None:
                        raise ProtocolError(f'{self.alias}: {error}')
                    split = (hdr_len, raw_len)
                    ipv6.__update__({
                        'fragment': self._read_packet(header=hdr_len, payload=raw_len),
                    })

                # NOTE: Only a first fragment goes on. :rfc:`8200#section-4.5`
                # puts every header through the upper-layer one in the fragment
                # at offset zero, so what follows its Fragment header is walked
                # exactly as it would be without one (#1539). A later
                # fragment carries a slice of the Fragmentable Part from its
                # offset on, and that slice starts with no header at all.
                if not self._is_first_fragment(info):
                    opaque = True
                    break

        # record real header & payload length (headers exclude)
        ipv6.__update__({
            'hdr_len': hdr_len if split is None else split[0],
            'raw_len': raw_len if split is None else split[1],

            # update next header
            'protocol': proto,

            # extension header chain in wire order, with the parser of each,
            # for ``from_data`` (#1473)
            '__exthdr__': tuple(_exthdr),
        })

        # NOTE: Nor does a later fragment's slice start with the upper-layer
        # header, though ``protocol`` above still names the one the first
        # fragment carries. No code is dispatched on, so the registry's
        # fallback leaves the octets as :class:`~pcapkit.protocols.misc.raw.Raw`
        # with no protocol to alias it as, and ``'UDP' in frame`` does not hold
        # of a slice of UDP payload (#1545). Reassembly takes
        # ``fragment`` above, which this leaves as it was.
        self._exthdr_depth = len(_protos)  # the headers the upper layer follows
        token = _frame_depth.set(depth + len(_protos))
        try:
            return super()._decode_next_layer(ipv6, None if opaque else proto, raw_len, packet=packet,
                                              ipv6_exthdr=ProtoChain.from_list(_protos),  # type: ignore[arg-type]
                                              payload=payload)
        finally:
            _frame_depth.reset(token)

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                           packet: 'Optional[dict[str, Any]]' = None, version: 'Literal[4, 6]' = 4,
                           extension: 'bool' = False, payload: 'Optional[bytes]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)
            version: IP protocol version
            extension: if is extension header
            payload: payload from packet. If not provided, will extract from
                :meth:`self.__header__.get_payload <pcapkit.protocols.schema.schema.Schema.get_payload>`

        Returns:
            Instance of next layer.

        Notes:
            A header whose dedicated parser raises reaches the
            :func:`~pcapkit.corekit.decorators.beholder` decorating this
            method, which substitutes plain
            :class:`~pcapkit.protocols.misc.raw.Raw`. That carries no ``next``,
            so :meth:`_decode_next_layer`'s walk stops there, as
            :rfc:`8200#section-4` has a node discard such a packet
            (:issue:`2477`). ``253`` and ``254`` have no dedicated parser and
            reach plain :class:`~pcapkit.protocols.misc.raw.Raw` with no
            exception involved, which stops the walk the same way. The layer
            the walk stopped on is then returned as the upper layer, not parsed
            again.
            :class:`~pcapkit.protocols.internet.esp.ESP`'s info always carries
            a ``next``, :data:`None` unless its payload was decrypted, since
            :rfc:`4303` encrypts the real value, so the walk ends after it.

            The upper layer past a walk cut at :data:`EXTENSION_HEADER_LIMIT
            <pcapkit.utilities.config.EXTENSION_HEADER_LIMIT>` is the
            next extension header, and is kept raw with one
            :exc:`~pcapkit.utilities.warnings.ProtocolWarning`, as in
            :meth:`Internet._import_next_layer
            <pcapkit.protocols.internet.internet.Internet._import_next_layer>`
            (:issue:`1604`).

        """
        upper, self._walk_upper = self._walk_upper, None
        if upper is not None:
            return upper

        if payload is None:
            file_ = self.__header__.get_payload()
        else:
            file_ = payload
        if length is None:
            length = len(file_)

        protocol, extra = self._next_layer_class(proto, file_, length, extension)
        return self._parse_next_layer(protocol, file_, length, version=version, extension=extension,
                                      alias=proto, packet=packet, layer=self._exlayer,
                                      protocol=self._exproto, __context__=self._exctx, **extra)
