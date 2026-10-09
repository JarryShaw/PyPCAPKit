# -*- coding: utf-8 -*-
"""IPv6 - Internet Protocol version 6
========================================

.. module:: pcapkit.protocols.internet.ipv6

:mod:`pcapkit.protocols.internet.ipv6` contains
:class:`~pcapkit.protocols.internet.ipv6.IPv6` only,
which implements extractor for Internet Protocol
version 6 (IPv6) [*]_, whose structure is described
as below:

======= ========= ===================== =======================================
Octets      Bits        Name                    Description
======= ========= ===================== =======================================
  0           0   ``ip.version``              Version (``6``)
  0           4   ``ip.class``                Traffic Class
  1          12   ``ip.label``                Flow Label
  4          32   ``ip.payload``              Payload Length (header excludes)
  6          48   ``ip.next``                 Next Header
  7          56   ``ip.limit``                Hop Limit
  8          64   ``ip.src``                  Source Address
  24        192   ``ip.dst``                  Destination Address
======= ========= ===================== =======================================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet

"""
import ipaddress
from typing import TYPE_CHECKING

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.utilities.decorators import beholder
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import ProtocolWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IPv6']


class IPv6(IP[Data_IPv6, Schema_IPv6],
           schema=Schema_IPv6, data=Data_IPv6):
    """This class implements Internet Protocol version 6."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Extension header codes with a *dedicated* parser class in this
    #: package whose layout follows :rfc:`6564#section-4`'s generic ``next`` +
    #: ``Hdr Ext Len`` format (see the module docstring of
    #: :mod:`pcapkit.protocols.internet.ipv6_ext` for the exception table).
    #: When that dedicated parser raises, :meth:`_import_next_layer`
    #: substitutes :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
    #: instead of letting the generic
    #: :func:`~pcapkit.utilities.decorators.beholder` fall back to plain
    #: :class:`~pcapkit.protocols.misc.raw.Raw`, which has no ``next`` field
    #: and so cannot continue the walk in :meth:`_decode_next_layer`.
    #:
    #: Three groups are deliberately absent:
    #:
    #: * :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`
    #:   has no dedicated parser (``pcapkit/protocols/internet/NotImplemented/shim6.py``
    #:   is a 0-byte placeholder), so there is no "own parser" for it to raise
    #:   from. It reaches :class:`IPv6_Ext` by *direct* registration (see the
    #:   bottom of :mod:`pcapkit.protocols.internet.ipv6_ext`), which already
    #:   produces exactly this class.
    #: * ``ESP`` *does* have a dedicated, registered parser
    #:   (:class:`~pcapkit.protocols.internet.esp.ESP`). It is excluded
    #:   because :rfc:`4303` places the real Next Header byte inside the
    #:   encrypted trailer, so its own info always *carries* a ``next``
    #:   attribute, just one that is :data:`None` whenever the payload could not
    #:   be decrypted -- which, with no key material available to a generic
    #:   parse, is always. The :meth:`_decode_next_layer` walk still ends
    #:   there, one iteration later, because :data:`None` fails
    #:   :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader`'s
    #:   constructor at the top of the loop -- the ordinary end-of-chain path,
    #:   unrelated to the structural check this set exists for.
    #: * ``253`` and ``254`` have no dedicated parser at all, so they resolve
    #:   to plain :class:`~pcapkit.protocols.misc.raw.Raw`, whose info has no
    #:   ``next`` *attribute*; the structural check in
    #:   :meth:`_decode_next_layer` catches these. A next-header byte that is
    #:   not in the extension-header registry at all (e.g. ``147``) fails the
    #:   same constructor at the top of the loop, like any unrecognised
    #:   upper-layer protocol code.
    #:
    #: :meth:`_decode_next_layer`'s walk stops cleanly at whichever of these
    #: (or any other IANA code this package has not implemented) it meets, and
    #: keeps this layer's own header intact.
    __generic_ext_codes__ = frozenset({
        Enum_ExtensionHeader.HOPOPT,
        Enum_ExtensionHeader.IPv6_Route,
        Enum_ExtensionHeader.IPv6_Opts,
        Enum_ExtensionHeader.Mobility_Header,
        Enum_ExtensionHeader.HIP,
        Enum_ExtensionHeader.IPv6_Frag,
        Enum_ExtensionHeader.AH,
    })

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
        return 40

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

        Structure of IPv6 header [:rfc:`2460`]:

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

        """
        if length is None:
            length = len(self)
        schema = self.__header__

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
        # c.f. :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>`
        # (:issue:`1209`).
        if schema.trailer:
            ipv6.__update__({
                'trailer': schema.trailer,
            })

        # NOTE: A jumbogram's extent is its Jumbo Payload Length, not the zero
        # Payload Length, c.f. :meth:`Schema_IPv6.post_process
        # <pcapkit.protocols.schema.internet.ipv6.IPv6.post_process>`
        # (:issue:`1434`). :rfc:`2675#section-2` makes a Jumbo Payload option
        # beside a non-zero Payload Length an error; such a packet is still
        # kept as captured, with the Payload Length deciding its extent, since
        # that is what the receiver had to go by.
        extent = schema.length
        jumbo = jumbo_payload_length(schema.next, schema.get_payload() + schema.trailer)
        if jumbo is not None:
            if schema.length == 0:
                extent = jumbo
            else:
                warn(f'{self.alias}: Jumbo Payload option with non-zero Payload Length '
                     f'{schema.length}; ignoring the Jumbo Payload Length {jumbo}',
                     ProtocolWarning, stacklevel=stacklevel())

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
                if that exceeds 65,535 octets.
            payload: Payload data.
            trailer: Octets after the packet, outside the Payload Length, such
                as link-layer padding; written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,
                                    reversed=next_reversed, pack=False)

        # NOTE: An explicit ``payload_length`` is written as given, so that a
        # ``from_data`` rebuild of a capture truncated by snaplen keeps the
        # length the sender declared instead of the one that was recorded
        # (:issue:`1155`). Computed from the octets at hand otherwise, which is
        # what a plain ``IPv6(payload=...)`` wants -- or zero for a payload too
        # long for the field, i.e. a jumbogram, whose length the caller carries
        # in a Jumbo Payload option of ``payload``'s Hop-by-Hop Options header
        # (:rfc:`2675#section-2`).
        if payload_length is None:
            payload_length = len(payload)
            if payload_length > 0xFFFF:
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
        return 40

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
        exthdr = data.get('__exthdr__')  # type: Optional[tuple[tuple[Type[ProtocolBase], Any], ...]] # pylint: disable=line-too-long
        exclude = ()  # type: tuple[str, ...]
        if exthdr is None:
            # NOTE: ``data`` was rebuilt from :meth:`Info.to_dict`, which leaves
            # ``__exthdr__`` out, so the chain is recovered from the keys the
            # extension headers were written under; those are no payload.
            exclude, exthdr = cls._lookup_exthdr(data)
        upper = cls._make_payload(data, exclude=exclude)
        payload = upper  # type: bytes | ProtocolBase

        # NOTE: The extension headers sit between this header and the upper
        # layer payload, so they are rebuilt in wire order ahead of it.
        if exthdr:
            payload = b''.join(proto.from_data(info).data for proto, info in exthdr) + upper.data

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
            # (:issue:`1155`).
            'payload_length': data.payload,
            'payload': payload,
            # NOTE: And the octets captured past the Payload Length (:issue:`1209`).
            'trailer': data.get('trailer', b''),
        }

    @classmethod
    def _lookup_exthdr(cls, data: 'Data_IPv6') -> 'tuple[tuple[str, ...], tuple[tuple[Type[ProtocolBase], Any], ...]]':  # pylint: disable=line-too-long
        """Recover the extension header chain of ``data`` without ``__exthdr__``.

        :meth:`_decode_next_layer` writes each extension header's info under a
        key of its own, in wire order, ahead of the upper layer. Walking the
        ``next`` field from :attr:`data.next <Data_IPv6.next>` names the parser
        of each in turn, exactly as the walk that parsed them did.

        Args:
            data: protocol data, without ``__exthdr__``

        Returns:
            The keys the extension headers are under, and the chain in the
            shape of ``__exthdr__``, i.e. the parser class and info of each.

        A header repeated in the chain is held under the same key as its
        predecessor, and ``data.items(multi=True)`` yields each of them in turn.

        """
        names = []  # type: list[str]
        chain = []  # type: list[tuple[Type[ProtocolBase], Any]]
        proto = data.get('next')
        nested = cls._lookup_nested(data)
        pairs = data.items(multi=True) if isinstance(data, (Info, MultiDict)) else data.items()
        for (key, info) in pairs:
            if key not in nested:
                continue
            try:
                ex_proto = Enum_ExtensionHeader(proto)
            except ValueError:
                break

            # NOTE: As in :meth:`_decode_next_layer`, a code with no parser
            # carrying ``next`` ends the chain, and so does a fragment header.
            if 'next' not in info:
                break
            names.append(key)
            chain.append((cls._lookup_next_layer(cls.__proto__, int(ex_proto)), info))

            proto = info['next']
            if ex_proto == Enum_ExtensionHeader.IPv6_Frag:
                break
        return tuple(names), tuple(chain)

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

        """
        #: Extension headers.
        self._exthdr = OrderedMultiDict()  # type: OrderedMultiDict[Enum_ExtensionHeader, ProtocolBase] # pylint: disable=attribute-defined-outside-init

        hdr_len = self.length       # header length
        raw_len = ipv6.payload if length is None else length  # payload length
        _protos = []                # ProtoChain buffer
        _exthdr = []                # (parser class, info) per extension header

        # traverse if next header is an extension header
        payload = self.__header__.get_payload()
        while True:
            try:
                ex_proto = Enum_ExtensionHeader(proto)
            except ValueError:
                break

            # # directly break when No Next Header occurs
            # if proto.name == 'IPv6-NoNxt':
            #     proto = None
            #     break

            # make protocol name
            next_ = self._import_next_layer(proto, packet=packet, version=6, extension=True,
                                            payload=payload)  # type: ignore[misc,call-arg,arg-type]
            info = next_.info

            # A layer with no ``next`` field cannot safely continue the walk.
            # This is a *structural* check, not a fixed set of codes: every
            # dedicated parser and
            # :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` carry
            # ``next`` (possibly :data:`None`, on an overrun) -- Shim6 has no
            # dedicated parser but is registered to ``IPv6_Ext`` directly --
            # while every other code with no dedicated parser -- ``253``,
            # ``254``, or whatever IANA assigns next -- resolves to plain
            # :class:`~pcapkit.protocols.misc.raw.Raw`, which does not (see
            # :attr:`__generic_ext_codes__`). Reading ``info.next`` on that
            # would raise ``AttributeError`` and let a further-out
            # :func:`~pcapkit.utilities.decorators.beholder` degrade the
            # *whole* packet.
            #
            # Such a layer is not recorded as an extension header: it consumed
            # nothing (``Raw.length`` is 0), so recording it would emit its
            # octets twice on rebuild, once from ``__exthdr__`` and once more as
            # the upper layer. Stopping here with ``proto`` unchanged instead
            # hands the remaining octets to ``super()._decode_next_layer``
            # below, which decodes them once, as the upper layer.
            if not hasattr(info, 'next'):
                break

            # NOTE: Added through a :class:`MultiDict`, so a repeated header
            # keeps its predecessor's info rather than overwriting it, and
            # :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
            # writes every one of them, in wire order (:issue:`1453`).
            name = next_.alias.lstrip('IPv6-').lower()
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
                ipv6.__update__({
                    'fragment': self._read_packet(header=hdr_len, payload=raw_len),
                })
                break

        # record real header & payload length (headers exclude)
        ipv6.__update__({
            'hdr_len': hdr_len,
            'raw_len': raw_len,

            # update next header
            'protocol': proto,

            # extension header chain in wire order, with the parser of each,
            # for ``from_data``
            '__exthdr__': tuple(_exthdr),
        })

        ipv6_exthdr = ProtoChain.from_list(_protos)  # type: ignore[arg-type]
        return super()._decode_next_layer(ipv6, proto, raw_len, packet=packet, ipv6_exthdr=ipv6_exthdr, payload=payload)

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
            If the dedicated parser for a code in :attr:`__generic_ext_codes__`
            raises, this substitutes
            :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` for it
            rather than letting the exception reach the
            :func:`~pcapkit.utilities.decorators.beholder` decorating this
            method, which would substitute plain
            :class:`~pcapkit.protocols.misc.raw.Raw` -- and ``Raw`` has no
            ``next`` field, so it could not continue
            :meth:`_decode_next_layer`'s walk. Every other exception --
            including one raised by ``IPv6_Ext`` itself, or by ``ESP``'s own
            dedicated parser -- still reaches ``beholder`` unchanged, giving a
            plain ``Raw`` for that one layer. ``253`` and ``254`` have no
            dedicated parser, so they reach plain ``Raw`` with no exception
            involved; :meth:`_decode_next_layer` stops its walk structurally on
            any layer whose info carries no ``next`` attribute, ``Raw``
            included. ``ESP``'s info always carries a ``next`` (:data:`None`,
            since :rfc:`4303` encrypts the real value), so neither this
            substitution nor that structural check engages for it, and the walk
            ends after it -- see :attr:`__generic_ext_codes__`'s docstring for
            the full distinction.

        """
        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'

        if payload is None:
            file_ = self.__header__.get_payload()
        else:
            file_ = payload
        if length is None:
            length = len(file_)

        if min(length, len(file_)) == 0:
            from pcapkit.protocols.misc.null import \
                NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import \
                Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self._lookup_next_layer(self.__proto__, proto)

        try:
            next_ = self._parse_next_layer(protocol, file_, length, version=version, extension=extension,
                                           alias=proto, packet=packet, layer=self._exlayer,
                                           protocol=self._exproto, __context__=self._exctx)
        except Exception as exc:
            from pcapkit.protocols.internet.ipv6_ext import \
                IPv6_Ext  # isort: skip # pylint: disable=import-outside-toplevel

            if not (extension and protocol is not IPv6_Ext
                    and proto in self.__generic_ext_codes__):
                raise

            next_ = IPv6_Ext(file_, length, version=version, extension=extension,
                             alias=proto, error=exc, packet=packet, layer=self._exlayer,
                             protocol=self._exproto, __context__=self._exctx)
        return next_
