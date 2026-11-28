# -*- coding: utf-8 -*-
"""STP - Spanning Tree Protocol
==================================

.. module:: pcapkit.protocols.application.stp.protocol

:mod:`pcapkit.protocols.application.stp.protocol` holds
:class:`~pcapkit.protocols.application.stp.protocol.STP`, the abstract base of the
Spanning Tree Protocol family [*]_, whose Bridge Protocol Data Units (BPDUs) are
told apart by their Protocol Version Identifier. Each version is a member of its
own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
     - BPDUs
   * - 0
     - :class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`
     - IEEE 802.1D-2004 clause 9
     - Configuration, 35 octets, and Topology Change Notification (TCN), 4 octets
   * - 2
     - :class:`~pcapkit.protocols.application.rstp.protocol.RSTP`
     - IEEE 802.1Q-2022 clause 14
     - RST, 36 octets
   * - 3
     - :class:`~pcapkit.protocols.application.mstp.protocol.MSTP`
     - IEEE 802.1Q-2022 clause 14
     - MST, 102 octets and an MSTI Configuration Message of 16 for each MSTI

The members share the first four octets alone, the Protocol Identifier, the Protocol
Version Identifier and the BPDU Type, so the base parses no BPDU. LLC address
``0x42`` is the family's, as DSAP and SSAP both, so
:attr:`LLC.__proto__ <pcapkit.protocols.link.llc.protocol.LLC.__proto__>` binds this
base, paired, and it picks the member as IEEE 802.1Q-2022 clause 14.4 validates a
BPDU, by :meth:`_classify`. A BPDU that clause discards is left
:class:`~pcapkit.protocols.misc.raw.protocol.Raw` behind LLC, and a direct parse of it
raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`; so is an SPT BPDU, of
version 4, which the family does not dissect.

The bridge's control plane computes the active topology rather than relaying
frames, so the family is a *user* of the stack, as a routing protocol is
(:doc:`/contributing/conventions/protocol-layer-placement`). The proprietary
per-VLAN variants, which no public specification defines, are not dissected.

.. [*] https://en.wikipedia.org/wiki/Spanning_Tree_Protocol

.. versionadded:: 1.9.0

"""
import abc
import collections.abc
from typing import TYPE_CHECKING, Generic, cast, overload

from pcapkit.const.llc.lsap import LSAP as Enum_LSAP
from pcapkit.const.stp.port_role import PortRole as Enum_PortRole
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.schema.short_read import cut_on_its_own
from pcapkit.corekit.sentinels import NO_VALUE, NoValueType
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.application.stp.data import BridgeID as Data_BridgeID
from pcapkit.protocols.application.stp.data import Flags as Data_Flags
from pcapkit.protocols.application.stp.data import PortID as Data_PortID
from pcapkit.protocols.protocol import _PT, _ST, _nothing_to_parse
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import IO, Any, Iterable, Mapping, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
    from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
    from pcapkit.corekit.context import ContextRegistry, ProtocolContext
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['STP']

#: tuple[tuple[int, ModuleDescriptor[STP]], ...]: Each version and the member that
#: reads it, resolved in :meth:`STP._member_of_version` rather than imported, so its
#: first import holds :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_MEMBERS = (
    (0, ModuleDescriptor('pcapkit.protocols.application.stpv0.protocol', 'STPv0')),
    (2, ModuleDescriptor('pcapkit.protocols.application.rstp.protocol', 'RSTP')),
    (3, ModuleDescriptor('pcapkit.protocols.application.mstp.protocol', 'MSTP')),
)  # type: tuple[tuple[int, ModuleDescriptor[STP]], ...]

#: tuple[ModuleDescriptor[Any], ...]: The members' data models, by which
#: :meth:`STP.from_data` picks the member, in the order of :data:`_MEMBERS`.
_DATA = (
    ModuleDescriptor('pcapkit.protocols.application.stpv0.data', 'STPv0'),
    ModuleDescriptor('pcapkit.protocols.application.rstp.data', 'RSTP'),
    ModuleDescriptor('pcapkit.protocols.application.mstp.data', 'MSTP'),
)  # type: tuple[ModuleDescriptor[Any], ...]


class STP(Application[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """This class implements all protocols in the Spanning Tree Protocol family.

    - Spanning Tree Protocol
      (:class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`) [IEEE 802.1D-2004]
    - Rapid Spanning Tree Protocol
      (:class:`~pcapkit.protocols.application.rstp.protocol.RSTP`) [IEEE 802.1Q-2022]
    - Multiple Spanning Tree Protocol
      (:class:`~pcapkit.protocols.application.mstp.protocol.MSTP`) [IEEE 802.1Q-2022]

    It is abstract, as :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` is,
    and dispatches on both paths, never giving an instance of this class
    (:issue:`2574`). The ``version`` keyword names the member, and :meth:`make` does
    not take it; without it, octets give the member :meth:`_classify` picks, and
    fields are refused. The Protocol Version Identifier alone does not pick it: a
    Configuration BPDU is one whatever its version, and an MST BPDU that fails its
    checks is an RST BPDU, so :meth:`from_data` reads the data model's class, as
    :meth:`LinuxSLL.from_data <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.from_data>`
    does. See :meth:`__new__`.

    Note:
        The subpackage does not track the dispatch tier. STP is dispatched from
        :attr:`LLC.__proto__ <pcapkit.protocols.link.llc.protocol.LLC.__proto__>`
        at :attr:`~pcapkit.const.llc.lsap.LSAP.Bridge_Spanning_Tree_Protocol`,
        since LLC is what carries it.

    """

    #: ``version``, which names the member and which :meth:`make` does not
    #: take, as a construction keyword (:issue:`2840`).
    __keywords__ = frozenset({'version'})

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    @abc.abstractmethod
    def version(self) -> 'Literal[0, 2, 3]':
        """Version of the member, the Protocol Version Identifier its BPDUs take."""

    @property
    def alias(self) -> 'str':
        """Acronym of current protocol, ``'STP'``, ``'RSTP'`` or ``'MSTP'``."""
        return self.id()[0]

    #: NOTE: On the base, as OSPF's is, so a consumer finds ``stp`` whichever
    #: member read the BPDU.
    @property
    def info_name(self) -> 'Literal["stp"]':
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'stp'

    @property
    def type(self) -> 'Enum_BPDUType':
        """BPDU Type."""
        return self._info.type  # type: ignore[attr-defined]

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["STP"], Literal["RSTP"], Literal["MSTP"]]':
        """Index ID of the protocol.

        IEEE 802.1D-2004 names the version 0 protocol ``STP``, without a version,
        so the family's own name doubles as its canonical name, the shape
        :meth:`IGMP.id <pcapkit.protocols.internet.igmp.protocol.IGMP.id>` takes.

        Returns:
            Index ID of the protocol, the family name and the RSTP and MSTP
            names; each member narrows it to its own canonical name.

        """
        return ('STP', 'RSTP', 'MSTP')

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', /, **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member whose data
            model ``data`` is.

        Raises:
            ProtocolError: If ``data`` is no member's data model, on this class. A
                :obj:`dict` is refused: its ``protocol_version`` does not pick the
                member, and no key does.

        """
        if cls is not STP:
            return super().from_data(data, **kwargs)
        for (_, member), model in zip(_MEMBERS, _DATA):
            if isinstance(data, model.klass):
                return cast('Self', member.klass.from_data(data, **kwargs))
        raise ProtocolError('STP: invalid data: must be an STPv0, RSTP or MSTP data model')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'Enum_LSAP':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in the LLC address values,
            which every member inherits, since no link type, EtherType, protocol
            number or port names it.

        """
        return Enum_LSAP.Bridge_Spanning_Tree_Protocol  # type: ignore[return-value]

    def __length_hint__(self) -> 'int':
        """Return an estimated length for the object.

        The longest member's fixed part, an MST BPDU with no MSTI, as
        :meth:`OSPF.__length_hint__
        <pcapkit.protocols.application.ospf.protocol.OSPF.__length_hint__>` takes
        its longest header.

        """
        return 102

    if not TYPE_CHECKING:
        # NOTE: For the docs' class signature (#1860): mypy rejects each overload of an abstract
        # class's ``__init__``, so it reads the one below and refuses this base as ``abstract`` (#3081).
        @overload  # pragma: no cover
        def __init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., /, *,
                     version: 'Optional[Literal[0, 2, 3]]' = ...,
                     layer: 'Optional[str]' = ...,
                     protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = ...,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                     ) -> 'None': ...
        @overload  # pragma: no cover
        def __init__(self, *, version: 'Optional[Literal[0, 2, 3]]' = ...,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                     **fields: 'Any') -> 'None': ...

    def __init__(self, file: 'IO[bytes] | bytes | NoValueType' = NO_VALUE,  # pylint: disable=super-init-not-called
                 length: 'Optional[int]' = None, /, *,
                 version: 'Optional[Literal[0, 2, 3]]' = None,
                 layer: 'Optional[str]' = None,
                 protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                 **fields: 'Any') -> 'None':
        """Parse a protocol instance from its octets, or construct one from its fields.

        Args:
            file: Source packet stream; omitted to construct.
            length: Length of packet data.
            version: Version of the member, ``0``, ``2`` or ``3``: the member
                :meth:`__new__` picks, which must be this class's own.
            layer: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            protocol: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            context: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            **fields: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If ``version`` names no member, or is not this class's
                own :attr:`version`.

        """
        if isinstance(file, NoValueType):
            if version is not None:
                fields['version'] = version
            self._construct(context, self._call_fields(length, layer, protocol, fields))
            return
        if version is not None:
            type(self)._construction_member({'version': version})
        # NOTE: ``_parse``, as the base's ``__init__`` takes no ``version`` (#2840).
        self._parse(file, length, fields, layer=layer, protocol=protocol, context=context)

    def __new__(cls, file: 'Optional[IO[bytes] | bytes] | NoValueType' = NO_VALUE,
                length: 'Optional[int]' = None, /, **kwargs: 'Any') -> 'STP':
        """Create the member a parse or a construction of this class describes.

        The ``version`` keyword names the member. Without it, the octets give the
        member :meth:`_classify` picks, and fields are refused. That member's
        ``__init__`` then runs with the same arguments. A subclass of this class
        is created as itself.

        Args:
            file: Source packet stream, read here without being consumed;
                omitted to construct.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            TypeError: If ``file`` is :obj:`None`, on this class.
            ProtocolError: On this class, if ``version`` names no member; if,
                without it, the octets are a BPDU IEEE 802.1Q-2022 clause 14.4
                discards; or if fields come without it.

        """
        if cls is not STP:
            return super().__new__(cls, file, length, **kwargs)
        if isinstance(file, NoValueType):
            member = cls._construction_member(kwargs)
            return member.__new__(member)
        if file is None:
            raise _nothing_to_parse(STP)
        version = kwargs.get('version')
        if version is None:
            if isinstance(file, bytes):
                data = file[:length]
            else:
                offset = file.tell()
                data = file.read(-1 if length is None else length)
                file.seek(offset)
            version = cls._classify(data)
            if version < 0:
                raise ProtocolError('STP: invalid format: no BPDU IEEE 802.1Q-2022 clause 14.4 validates')
        member = cls._member_of_version(version)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[STP]':
        """The member a ``version`` of ``0``, ``2`` or ``3`` names.

        Args:
            version: Version of the member, as :meth:`_classify` returns it or the
                ``version`` keyword gives it.

        Returns:
            :class:`~pcapkit.protocols.application.stpv0.protocol.STPv0` for ``0``,
            :class:`~pcapkit.protocols.application.rstp.protocol.RSTP` for ``2`` and
            :class:`~pcapkit.protocols.application.mstp.protocol.MSTP` for ``3``.

        Raises:
            ProtocolError: For any other ``version``, or one that is no :obj:`int`, as
                a :obj:`bool` is even where it equals one.

        """
        if isinstance(version, int) and not isinstance(version, bool):
            for number, member in _MEMBERS:
                if version == number:
                    return member.klass
        raise ProtocolError(f'STP: invalid version: {version!r}')

    @classmethod
    def _classify(cls, data: 'bytes') -> 'Literal[-1, 0, 2, 3]':
        """Validate a received BPDU as IEEE 802.1Q-2022 clause 14.4 does.

        With a Protocol Identifier of zero, a BPDU Type of ``0x00`` and 35 octets
        or more is a Configuration BPDU, and one of ``0x80`` and 4 octets or more
        a TCN BPDU, whatever the version; with a BPDU Type of ``0x02``, a version
        of 2 and 36 octets or more is an RST BPDU. A version of 3 or more, with 35
        octets or more, is an RST BPDU where :meth:`_is_mst` fails; where it holds,
        version 3 is an MST BPDU, and a later version the SPT BPDU of Shortest Path
        Bridging, version 4, which extends it and which no member reads. Anything
        else is discarded.

        Args:
            data: The BPDU, its octets alone.

        Returns:
            ``0``, ``2`` or ``3``, the version of the member that reads it, or
            ``-1`` for a BPDU the clause discards or no member reads.

        """
        if len(data) < 4 or data[:2] != b'\x00\x00':
            return -1
        version, type_ = data[2], data[3]
        if type_ == 0x00:
            return 0 if len(data) >= 35 else -1
        if type_ == 0x80:
            return 0
        if type_ != 0x02 or version < 2:
            return -1
        if version == 2:
            return 2 if len(data) >= 36 else -1
        if len(data) < 35:
            return -1
        if not cls._is_mst(data):
            return 2
        return 3 if version == 3 else -1

    @staticmethod
    def _is_mst(data: 'bytes') -> 'bool':
        """Whether a BPDU of version 3 or more holds what an MST BPDU does.

        It holds 102 octets or more, a Version 1 Length of zero, and a Version 3
        Length counting 0 to 64 MSTI Configuration Messages of 16 octets each after
        the 64 octets every MST BPDU has there (IEEE 802.1Q-2022 clause 14.4).

        Args:
            data: The BPDU, its octets alone.

        Returns:
            Whether it is an MST BPDU, rather than an RST BPDU.

        """
        if len(data) < 102 or data[35] != 0:
            return False
        extra = int.from_bytes(data[36:38], 'big') - 64
        return extra >= 0 and extra % 16 == 0 and extra // 16 <= 64

    @classmethod
    def _construction_member(cls, fields: 'dict[str, Any]') -> 'Type[Self]':
        """The member :meth:`from_fields`, :meth:`from_data` and a call given no file construct.

        On this class, the member ``version`` names; on another, the class itself,
        whose :attr:`version` ``version`` must be. ``version`` is taken out of
        ``fields``, as :meth:`make` does not read it.

        Args:
            fields: Construction keywords.

        Returns:
            The member, or the class itself.

        Raises:
            ProtocolError: If, on this class, ``version`` is missing; if it names
                no member; or if it is not the class's own :attr:`version`.

        """
        version = fields.pop('version', None)
        if cls is STP:
            if version is None:
                raise ProtocolError('STP: no version to build with; pass version=0, 2 or 3')
            return cast('Type[Self]', cls._member_of_version(version))
        if version is not None:
            cls._member_of_version(version)
            # NOTE: ``version`` is a property, read as ``__init__`` reads it, off a bare instance.
            if version != cls.__new__(cls).version:
                raise ProtocolError(f'{cls.__name__}: version={version!r} names another member')
        return cls

    @staticmethod
    def _rebuilt_version(data: 'Any', own: 'int') -> 'int':
        """The version a rebuild of ``data`` writes: its own, or ``own`` if the capture ended first.

        A capture that ends before the Protocol Version Identifier leaves it zero,
        which names no RST or MST BPDU's version; the rebuild is cut back before the
        octet, so the version it writes is never read, as for
        :meth:`OSPF._rebuilt_version
        <pcapkit.protocols.application.ospf.protocol.OSPF._rebuilt_version>`.

        Args:
            data: The data model being rebuilt.
            own: The version of the member rebuilding it.

        Returns:
            The version for :meth:`make`.

        """
        record = data.get('__short_read__')
        if record is not None and (record[0] == 'pid' or tuple(record) == ('version', 0)):
            return own
        return data.protocol_version

    def _check_bpdu(self, schema: 'Schema', *, types: 'tuple[int, ...]', least: 'int' = 0,
                    most: 'int' = 0xFF) -> 'None':
        """Refuse a BPDU another member reads, or one no member does.

        Its Protocol Identifier must be zero, its BPDU Type one of ``types`` and its
        Protocol Version Identifier from ``least`` to ``most``. A field a header
        parsed on its own ends before is left to the short read, as its zeros are
        the cut's.

        Args:
            schema: The header just parsed.
            types: The BPDU Types this member reads.
            least: The lowest Protocol Version Identifier it reads.
            most: The highest.

        Raises:
            ProtocolError: If one of them is not, and was read.

        """
        pid, version, type_ = schema.pid, schema.version, schema.type  # type: ignore[attr-defined]
        if not cut_on_its_own(schema, 'pid') and pid != 0:
            raise ProtocolError(f'{self.alias}: invalid Protocol Identifier: {pid:#06x}')
        if not cut_on_its_own(schema, 'version') and not least <= version <= most:
            raise ProtocolError(f'{self.alias}: invalid Protocol Version Identifier: {int(version)}')
        if not cut_on_its_own(schema, 'type') and type_ not in types:
            raise ProtocolError(f'{self.alias}: invalid BPDU Type: {int(type_):#04x}')

    def _read_bridge_id(self, octets: 'bytes') -> 'Data_BridgeID':
        """Read a Bridge Identifier.

        Args:
            octets: Its eight octets; fewer where a cut ended them, the rest read
                as zeros.

        Returns:
            Parsed Bridge Identifier.

        """
        octets = octets.ljust(8, b'\x00')
        return Data_BridgeID(
            priority=(octets[0] & 0xF0) << 8,
            extension=(octets[0] & 0x0F) << 8 | octets[1],
            address=self._read_mac_addr(octets[2:8]),
        )

    def _make_bridge_id(self, value: 'Data_BridgeID | bytes', *, name: 'str') -> 'bytes':
        """Make a Bridge Identifier.

        Args:
            value: The identifier, as its data model or a mapping of its keys, or
                its eight octets.
            name: Name of the field, for the error message.

        Returns:
            Its eight octets.

        Raises:
            ProtocolError: If ``value`` is neither; if its priority is not a multiple
                of 4096 in ``0..61440``; or if its extension does not fit in 12 bits,
                or its address is no MAC address.

        """
        if isinstance(value, (bytes, bytearray)):
            return self._make_octets(value, size=8, name=name)
        if not isinstance(value, collections.abc.Mapping):
            raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')
        priority = self._make_uint(value['priority'], bits=16, name=f'{name} priority')
        if priority & 0x0FFF:
            raise ProtocolError(f'{self.alias}: invalid {name} priority: {priority!r} is not a multiple of 4096')
        extension = self._make_uint(value['extension'], bits=12, name=f'{name} extension')
        address = self._make_mac_addr(value['address'], name=f'{name} address')
        return (priority | extension).to_bytes(2, 'big') + address

    @staticmethod
    def _read_port_id(value: 'int') -> 'Data_PortID':
        """Read a Port Identifier.

        Args:
            value: Its two octets, as an integer.

        Returns:
            Parsed Port Identifier.

        """
        return Data_PortID(
            priority=(value >> 8) & 0xF0,
            number=value & 0x0FFF,
        )

    def _make_port_id(self, value: 'Data_PortID | int', *, name: 'str') -> 'int':
        """Make a Port Identifier.

        Args:
            value: The identifier, as its data model or a mapping of its keys, or
                its two octets as an integer.
            name: Name of the field, for the error message.

        Returns:
            Its two octets, as an integer.

        Raises:
            ProtocolError: If ``value`` is neither; if its priority is not a multiple
                of 16 in ``0..240``; or if its number does not fit in 12 bits.

        """
        if not isinstance(value, collections.abc.Mapping):
            return self._make_uint(value, bits=16, name=name)
        priority = self._make_uint(value['priority'], bits=8, name=f'{name} priority')
        if priority & 0x0F:
            raise ProtocolError(f'{self.alias}: invalid {name} priority: {priority!r} is not a multiple of 16')
        return priority << 8 | self._make_uint(value['number'], bits=12, name=f'{name} number')

    @staticmethod
    def _read_flags(value: 'int') -> 'Data_Flags':
        """Read the flags of an RST or MST BPDU.

        Args:
            value: The flags octet.

        Returns:
            Parsed flags.

        """
        return Data_Flags(
            tc=bool(value & 0x01),
            proposal=bool(value & 0x02),
            role=Enum_PortRole.get((value >> 2) & 0b11),
            learning=bool(value & 0x10),
            forwarding=bool(value & 0x20),
            agreement=bool(value & 0x40),
            tc_ack=bool(value & 0x80),
        )

    def _make_flags(self, value: 'Data_Flags | int') -> 'int':
        """Make the flags of an RST or MST BPDU.

        Args:
            value: The flags, as their data model or a mapping of its keys, or the
                octet as an integer.

        Returns:
            The flags octet.

        Raises:
            ProtocolError: If ``value`` is neither, or a flag is no :obj:`bool` or
                the role does not fit in two bits.

        """
        if not isinstance(value, collections.abc.Mapping):
            return self._make_uint(value, bits=8, name='flags')
        return self._make_role_flags(value, last='tc_ack', name='Topology Change Acknowledgment flag')

    def _make_role_flags(self, value: 'Mapping[str, Any]', *, last: 'str', name: 'str') -> 'int':
        """Make a flags octet carrying a Port Role, the CIST's or an MSTI's.

        Args:
            value: The flags.
            last: Key of the flag in bit 8.
            name: Name of the flag in bit 8, for the error message.

        Returns:
            The flags octet.

        Raises:
            ProtocolError: If a flag is no :obj:`bool`, or the role does not fit in
                two bits.

        """
        role = self._make_index(value['role'], Enum_PortRole, bits=2, name='port role')
        return (self._make_uint(value['tc'], bits=1, name='Topology Change flag')
                | self._make_uint(value['proposal'], bits=1, name='Proposal flag') << 1
                | int(role) << 2
                | self._make_uint(value['learning'], bits=1, name='Learning flag') << 4
                | self._make_uint(value['forwarding'], bits=1, name='Forwarding flag') << 5
                | self._make_uint(value['agreement'], bits=1, name='Agreement flag') << 6
                | self._make_uint(value[last], bits=1, name=name) << 7)

    @staticmethod
    def _read_timer(value: 'int') -> 'float':
        """Read a timer, in units of 1/256 of a second (IEEE 802.1D-2004 clause 9).

        Args:
            value: Its two octets, as an integer.

        Returns:
            The timer, in seconds, exact as 256 is a power of two.

        """
        return value / 256

    def _make_timer(self, value: 'float | int', *, name: 'str') -> 'int':
        """Make a timer, in units of 1/256 of a second.

        Args:
            value: The timer, in seconds.
            name: Name of the timer, for the error message.

        Returns:
            Its two octets, as an integer.

        Raises:
            ProtocolError: If ``value`` is no number of seconds, a :obj:`bool`
                included, is not a multiple of 1/256, or does not fit in 16 bits.

        """
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            ticks = value * 256
            if float(ticks).is_integer() and 0 <= ticks < 0x10000:
                return int(ticks)
        raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')

    def _make_protocol_version(self, value: 'Enum_ProtocolVersion | int', *, least: 'int',
                               most: 'int' = 0xFF) -> 'int':
        """Check a Protocol Version Identifier this member writes.

        Args:
            value: The Protocol Version Identifier.
            least: The lowest version this member's BPDUs take.
            most: The highest.

        Returns:
            ``value``, as a plain :class:`int`.

        Raises:
            ProtocolError: If ``value`` is no 8-bit code, or is outside ``least`` to
                ``most``.

        """
        version = self._make_uint(value, bits=8, name='Protocol Version Identifier')
        if not least <= version <= most:
            raise ProtocolError(f'{self.alias}: invalid Protocol Version Identifier: {version}, '
                                f'which an {self.alias} BPDU does not take')
        return version
