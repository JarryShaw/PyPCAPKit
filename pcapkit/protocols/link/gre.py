# -*- coding: utf-8 -*-
"""GRE - Generic Routing Encapsulation
=========================================

.. module:: pcapkit.protocols.link.gre

:mod:`pcapkit.protocols.link.gre` contains
:class:`~pcapkit.protocols.link.gre.GRE` only, which implements the extractor
for the Generic Routing Encapsulation base header [:rfc:`2784`] plus the
optional Key and Sequence Number extensions [:rfc:`2890`], as seen on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_IPGRE`` or ``ARPHRD_IP6GRE`` -- both land on this one class:
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` dispatches here instead
of falling back to :class:`~pcapkit.protocols.misc.raw.Raw` for either case;
see :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`. The
"IP"/"IP6" distinction in the two ``arphrd_type`` names is about which IP
version the tunnel carries on its *outer* layer -- i.e. which ``arphrd_type``
fired -- not a different GRE header shape; the GRE framing itself is
identical either way.

Structure, the base header plus every optional field (:rfc:`2784` section
2.1, :rfc:`2890` section 2):

.. code-block:: text

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |C| |K|S| Reserved0       | Ver |         Protocol Type         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Checksum (optional)      |       Reserved1 (optional)    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Key (optional)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Sequence Number (optional)                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

``C`` gates the Checksum/Reserved1 pair, ``K`` gates the Key field and ``S``
gates the Sequence Number field, each independently -- so the header is
4, 8, 12 or 16 octets depending on which of the three are set. ``Ver`` is
:rfc:`2784`'s 3-bit Version Number, which MUST be ``0``; a nonzero version is
a different protocol entirely (RFC 2637's "Enhanced GRE", the PPTP variant,
is version ``1``) and is not implemented here. The Protocol Type field is an
EtherType selecting the encapsulated payload -- resolved through
:attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`, the same
family registry Ethernet, VLAN and LinuxSLL already share, exactly as
:class:`~pcapkit.protocols.link.vlan.VLAN` resolves its own ``type`` field.
This class therefore keeps no registry of its own.

Scope
-----

Only the framing above is dissected. The Key and Sequence Number fields are
recorded but not interpreted further -- their meaning (which traffic flow, and
where in its sequence) is a matter for the tunnel endpoints, not something a
passive dissector can resolve from the header alone. RFC 2637's Enhanced GRE
(version 1, used by PPTP) has a different, incompatible layout from this point
on -- a Key field split into Payload Length and Call ID, and an optional
Acknowledgment Number -- and is out of scope; :meth:`read` refuses it rather
than misreading it as RFC 2784/2890 GRE.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.linux.arphrd import ARPHRD as Enum_ARPHRD
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.data.link.gre import GRE as Data_GRE
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.gre import GRE as Schema_GRE
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['GRE']


class GRE(Link[Data_GRE, Schema_GRE],
         schema=Schema_GRE, data=Data_GRE):
    """This class implements Generic Routing Encapsulation (GRE).

    The Protocol Type field is dispatched as an EtherType through
    :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`,
    exactly as :class:`~pcapkit.protocols.link.vlan.VLAN` resolves its own
    ``type`` field -- so, unlike
    :class:`~pcapkit.protocols.link.frad.FRAD`, this class declares no
    registry of its own.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Generic Routing Encapsulation"]':
        """Name of current protocol."""
        return 'Generic Routing Encapsulation'

    @property
    def alias(self) -> 'Literal["GRE"]':
        """Acronym of corresponding protocol."""
        return 'GRE'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.len

    @property
    def protocol(self) -> 'Enum_EtherType':
        """Name of next layer protocol."""
        return self._info.protocol_type

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["GRE"]]':
        """Index ID of the protocol."""
        return ('GRE',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_GRE':  # pylint: disable=unused-argument
        """Read Generic Routing Encapsulation (GRE) frame.

        Structure of a GRE frame, with every optional field present; see the
        module docstring for the full diagram:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |C| |K|S| Reserved0       | Ver |         Protocol Type         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Version Number is not ``0`` -- see the
                module docstring's *Scope* section.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        flags = schema.flags
        if flags['version']:
            raise ProtocolError(f'{self.alias}: invalid version: {flags["version"]}')

        _hdr_len = 4
        _checksum = None  # type: Optional[int]
        _reserved1 = None  # type: Optional[int]
        if flags['checksum_present']:
            _checksum = schema.checksum
            _reserved1 = schema.reserved1
            _hdr_len += 4

        _key = None  # type: Optional[int]
        if flags['key_present']:
            _key = schema.key
            _hdr_len += 4

        _sequence_number = None  # type: Optional[int]
        if flags['sequence_present']:
            _sequence_number = schema.sequence_number
            _hdr_len += 4

        gre = Data_GRE(
            checksum_present=bool(flags['checksum_present']),
            key_present=bool(flags['key_present']),
            sequence_present=bool(flags['sequence_present']),
            reserved=(flags['reserved_1'] << 14) | (flags['reserved_2'] << 3),
            version=flags['version'],
            protocol_type=schema.protocol_type,
            checksum=_checksum,
            reserved1=_reserved1,
            key=_key,
            sequence_number=_sequence_number,
            len=_hdr_len,
        )
        return self._decode_next_layer(gre, schema.protocol_type, length - _hdr_len)

    def make(self,
             checksum: 'Optional[int]' = None,
             reserved1: 'Optional[int]' = None,
             key: 'Optional[int]' = None,
             sequence_number: 'Optional[int]' = None,
             reserved: 'int' = 0,
             version: 'Literal[0]' = 0,
             protocol_type: 'Enum_EtherType | StdlibEnum | AenumEnum | str | int' = Enum_EtherType.Internet_Protocol_version_4,  # pylint: disable=line-too-long
             protocol_type_default: 'Optional[int]' = None,
             protocol_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             protocol_type_reversed: 'bool' = False,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_GRE':
        """Make (construct) packet data.

        The presence of each optional field is inferred from whether its
        value is given, as :meth:`L2TPv2.make
        <pcapkit.protocols.link.l2tpv2.L2TPv2.make>` infers ``S`` from
        whether ``ns``/``nr`` are given: passing ``checksum`` sets ``C``,
        ``key`` sets ``K``, and ``sequence_number`` sets ``S``.

        Args:
            checksum: Checksum; setting this also sets ``C``.
            reserved1: Reserved1; only meaningful, and only accepted, when
                ``checksum`` is also given. Defaults to ``0`` when
                ``checksum`` is given and this is not.
            key: Key, :rfc:`2890`; setting this also sets ``K``.
            sequence_number: Sequence Number, :rfc:`2890`; setting this also
                sets ``S``.
            reserved: Reserved bits of the flags word, in their on-wire
                positions (bit 1 and bits 4-12, i.e. within ``0x4FF8``).
            version: Version Number; :rfc:`2784` fixes this at ``0``.
            protocol_type: Protocol Type: the EtherType of the encapsulated
                payload.
            protocol_type_default: Default value of ``protocol_type``.
            protocol_type_namespace: Namespace of ``protocol_type``.
            protocol_type_reversed: Reversed namespace of ``protocol_type``.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``reserved1`` is given without ``checksum``; if
                ``reserved`` sets a bit outside ``0x4FF8``; if ``version``
                does not fit in 3 bits; or if ``checksum``, ``key`` or
                ``sequence_number`` is given but does not fit the width of
                its field (16 bits for ``checksum``, 32 bits for ``key`` and
                ``sequence_number``).

        """
        protocol_type_ = self._make_index(protocol_type, protocol_type_default,
                                          namespace=protocol_type_namespace,
                                          reversed=protocol_type_reversed, pack=False)

        checksum_present = checksum is not None
        if reserved1 is not None and not checksum_present:
            raise ProtocolError(f'{self.alias}: reserved1 given without checksum')
        if checksum_present:
            checksum = self._make_uint(checksum, bits=16, name='checksum')
            if reserved1 is None:
                reserved1 = 0
            else:
                reserved1 = self._make_uint(reserved1, bits=16, name='reserved1')

        key_present = key is not None
        if key_present:
            key = self._make_uint(key, bits=32, name='key')

        sequence_present = sequence_number is not None
        if sequence_present:
            sequence_number = self._make_uint(sequence_number, bits=32, name='sequence_number')

        if reserved & ~0x4FF8:
            raise ProtocolError(f'{self.alias}: reserved bits outside 0x4FF8: {reserved:#06x}')
        self._make_uint(version, bits=3, name='version')

        return Schema_GRE(
            flags={
                'checksum_present': checksum_present,
                'reserved_1': (reserved >> 14) & 0b1,
                'key_present': key_present,
                'sequence_present': sequence_present,
                'reserved_2': (reserved >> 3) & 0x1FF,
                'version': version,
            },
            protocol_type=protocol_type_,  # type: ignore[arg-type]
            checksum=checksum,
            reserved1=reserved1,
            key=key,
            sequence_number=sequence_number,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object.

        The longest form -- every optional field present, 16 octets -- per
        the reason :meth:`L2TPv2.__length_hint__
        <pcapkit.protocols.link.l2tpv2.L2TPv2.__length_hint__>` gives for a
        variable-length header: the shortest form would reject a fully
        captured longer header as too short.

        """
        return 16

    @classmethod
    def __index__(cls) -> 'Enum_ARPHRD':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in Linux ARP hardware
            types: :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IPGRE`, which
            :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`
            dispatches here alongside
            :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IP6GRE`.

        """
        return Enum_ARPHRD.IPGRE  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_GRE') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'checksum': data.checksum,
            'reserved1': data.reserved1,
            'key': data.key,
            'sequence_number': data.sequence_number,
            'reserved': data.reserved,
            'version': data.version,
            'protocol_type': data.protocol_type,
            'payload': cls._make_payload(data),
        }
