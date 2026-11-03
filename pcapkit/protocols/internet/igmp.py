# -*- coding: utf-8 -*-
"""IGMP - Internet Group Management Protocol
===============================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` contains
:class:`~pcapkit.protocols.internet.igmp.IGMP`, the abstract base of
IGMPv1 (:rfc:`1112`), IGMPv2 (:rfc:`2236`) and IGMPv3 (:rfc:`3376`) messages.
IGMPv1 and IGMPv2 share one 8-octet layout, so the base holds that shared
schema, data model and read path. :class:`~pcapkit.protocols.internet.igmpv1.IGMPv1`,
:class:`~pcapkit.protocols.internet.igmpv2.IGMPv2` and
:class:`~pcapkit.protocols.internet.igmpv3.IGMPv3` set :attr:`version`; IGMPv3's
wire format differs materially (a Query's source-list extension, a Report's
group-record list), so it carries its own schema and data model instead. The
registry entry for IP protocol 2 is this base, and :meth:`IGMP._dispatch
<pcapkit.protocols.internet.igmp.IGMP._dispatch>` picks the version class.
Constructing the base gives the class its ``version`` keyword names; without it,
octets give the class ``_dispatch`` picks, and fields are refused.
:meth:`~pcapkit.protocols.internet.igmp.IGMP.from_data` gives the class the
``version`` of its data names, which each data model carries and no octet does
(:issue:`2574`). Every version's checksum covers the whole message, with no
pseudo-header, so the base verifies it for each of them (:issue:`2618`).

.. versionadded:: 1.6.0

"""

import abc
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.igmp.type import Type as Enum_Type
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.igmp import IGMP as Data_IGMP
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.protocols.schema.internet.igmp import IGMP as Schema_IGMP
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import IO, Any, Literal, Optional, Type

    from typing_extensions import Self

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IGMP']


class IGMP(Internet[_PT, _ST], Generic[_PT, _ST],
           schema=Schema_IGMP, data=Data_IGMP):
    """This class implements Internet Group Management Protocol.

    The class is abstract: :attr:`version` is set by the concrete IGMPv1,
    IGMPv2 and IGMPv3 classes. :meth:`read` refuses a message that
    :meth:`_classify` does not place in :attr:`version`.

    It dispatches on both paths, never giving an instance of this class
    (:issue:`2574`). ``version`` names the version class; without it, octets
    give the one :meth:`_dispatch` picks, and fields are refused, since no field
    picks a class. :meth:`from_data` reads the ``version`` of its data. See
    :meth:`__new__`.

    The checksum of every version is verified on read under
    :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, unless the enclosing IP
    layer is a fragment, see :meth:`_verify_checksum`; :meth:`make` computes
    one it is not given.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Group Management Protocol"]':
        """Name of corresponding protocol."""
        return 'Internet Group Management Protocol'

    @property
    @abc.abstractmethod
    def version(self) -> 'Literal[1, 2, 3]':
        """IGMP version this class reads: ``1``, ``2`` or ``3``."""

    @property
    def alias(self) -> 'str':
        """Acronym of corresponding protocol, ``'IGMP'``, ``'IGMPv2'`` or ``'IGMPv3'``.

        IGMPv1 reports ``'IGMP'``, the name :rfc:`1112` gives it.

        """
        return f'IGMPv{self.version}'

    @property
    def length(self) -> 'Literal[8]':
        """Header length of current protocol."""
        return 8

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IGMP"], Literal["IGMPv2"], Literal["IGMPv3"]]':
        """Index ID of the protocol.

        :rfc:`1112` names the protocol ``IGMP``, without a version, the same
        shape :class:`~pcapkit.protocols.internet.icmp.ICMP` takes for
        :rfc:`792` -- so the family base's own name doubles as IGMPv1's
        canonical name. :rfc:`2236` and :rfc:`3376` name IGMPv2 and IGMPv3
        with their own versions.

        Returns:
            Index ID of the protocol, the family name and the IGMPv2 and
            IGMPv3 names; the concrete IGMPv1, IGMPv2 and IGMPv3 classes
            narrow it to their own canonical name.

        """
        return ('IGMP', 'IGMPv2', 'IGMPv3')

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> '_PT':
        """Read Internet Group Management Protocol.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            ProtocolError: If :meth:`_classify` does not place the message in
                :attr:`version`.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = cast('Schema_IGMP', self.__header__)

        if self._classify(schema.type, schema.max_resp_time, length) != self.version:
            raise ProtocolError(f'{self.alias}: {schema.type!r} is not an IGMPv{self.version} '
                                f'message ({length} octets)')

        igmp = cast('_PT', Data_IGMP(
            version=self.version,  # type: ignore[arg-type]
            type=schema.type,
            max_resp_time=schema.max_resp_time,
            checksum=schema.checksum,
            group=schema.group,
        ))
        self._verify_checksum(igmp, schema.checksum, length)
        # NOTE: IGMPv1/v2 has no next-protocol field, so trailing octets stay
        # as ``Raw``.
        return self._decode_next_layer(igmp, None, length - self.length)

    def make(self,
             type: 'Enum_Type | int' = Enum_Type.IGMP_Membership_Query,
             max_resp_time: 'int' = 0,
             checksum: 'Optional[bytes]' = None,
             group: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        The version of a constructed message is decided by its ``type``,
        ``max_resp_time`` and length (see :meth:`_classify`), not by the class
        that built it.

        Args:
            type: Message type.
            max_resp_time: Max response time, in tenths of a second; zero for
                an IGMPv1 message.
            checksum: Checksum over the message with this field zeroed, no
                pseudo-header (:rfc:`2236#section-2.3`); if :data:`None`,
                computed over the message, ``payload`` included, when
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on, zero
                when it is off.
            group: Group address; ``0.0.0.0`` for a General Query.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is a name, a :obj:`bool`, or a member
                or code outside 0 to 255, ``max_resp_time`` is not a
                non-:obj:`bool` integer from 0 to 255, or ``checksum`` is not
                two octets.

        """
        type_value = self._make_index(type, Enum_Type, bits=8, name='type')
        max_resp_time = self._make_uint(max_resp_time, bits=8, name='max_resp_time')

        schema = Schema_IGMP(
            type=type_value,
            max_resp_time=max_resp_time,
            checksum=b'\x00\x00' if checksum is None else self._make_octets(checksum, size=2, name='checksum'),
            group=group,
            payload=payload,
        )

        if checksum is None and config.CHECKSUM_COMPUTE:
            from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
            schema.checksum = compute_checksum(schema.pack())
        return schema  # type: ignore[return-value]

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the version class
            the ``version`` of ``data`` names, which every IGMP data model
            carries (:issue:`2574`).

        Raises:
            ProtocolError: If ``data`` carries no ``version``, or one that names
                no version class, on this class.

        """
        if cls is not IGMP:
            return super().from_data(data, **kwargs)
        version = data.get('version')
        if version is None:
            raise ProtocolError('IGMP: invalid data: must carry a version of 1, 2 or 3')
        member = cls._member_of_version(version)
        return cast('Self', member.from_data(data, **kwargs))

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IGMP  # type: ignore[return-value]

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object."""
        return 8

    def __init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                 length: 'Optional[int]' = None, *,
                 version: 'Optional[Literal[1, 2, 3]]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: Version of IGMP, ``1``, ``2`` or ``3``: the class
                :meth:`__new__` picks. Building from fields, it must be this
                class's :attr:`version`. Parsing, it is handed on unread, as the
                enclosing IP layer passes its own version under this name to the
                layer it carries.
            **kwargs: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If, building from fields, ``version`` names no version
                class, or is not this class's own :attr:`version`, which every
                IGMP class states, a subclass outside the members included.

        """
        if file is not None:
            if version is not None:
                kwargs['version'] = version
        elif version is not None:
            self._member_of_version(version)
            if version != self.version:
                raise ProtocolError(f'{type(self).__name__}: version={version!r} '
                                    'names another member')
        super().__init__(file, length, **kwargs)  # type: ignore[arg-type]

    def __new__(cls, file: 'Optional[IO[bytes] | bytes]' = None,
                length: 'Optional[int]' = None, **kwargs: 'Any') -> 'IGMP':
        """Create the version class a construction of this class describes.

        The ``version`` keyword names the class, on either path. Without it,
        parsing octets gives the class :meth:`_dispatch` picks, and building from
        fields is refused, since no field picks a class. That class's
        ``__init__`` then runs with the same arguments. A subclass of this class
        is created as itself.

        Args:
            file: Source packet stream, read here without being consumed.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the version class.

        Raises:
            ProtocolError: If ``version`` names no version class; or, without it,
                if building from fields, or if the octets are no version's
                message.

        """
        if cls is not IGMP:
            return super().__new__(cls, file, length, **kwargs)
        version = kwargs.get('version')
        if version is not None:
            member = cls._member_of_version(version)
        elif file is None:
            raise ProtocolError('IGMP: no version to build with; pass version=1, 2 or 3')
        else:
            if isinstance(file, bytes):
                data = file[:length]
            else:
                offset = file.tell()
                data = file.read(length)  # type: ignore[arg-type]
                file.seek(offset)
            from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel

            picked = cls._dispatch(data, len(data))
            if picked is Raw:
                raise ProtocolError('IGMP: unknown version')
            member = cast('Type[IGMP]', picked)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IGMP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'version': data.get('version'),
            'type': data.type,
            'max_resp_time': data.max_resp_time,
            'checksum': data.checksum,
            'group': data.group,
            'payload': cls._make_payload(data),
        }

    @classmethod
    def _classify(cls, type: 'Enum_Type | int', max_resp_time: 'int',
                  length: 'int') -> 'Literal[0, 1, 2, 3]':
        """Classify a parsed IGMP header as IGMPv1, IGMPv2 or IGMPv3.

        A Membership Query is IGMPv1/v2 only at exactly 8 octets: IGMPv1 if
        ``max_resp_time`` is zero, IGMPv2 otherwise. A Membership Query of 12
        or more octets is IGMPv3's Query, carrying the source-list extension
        (:rfc:`3376#section-7.1`); one of 9 to 11 octets is neither and is
        ignored. The IGMPv3 Membership Report (``0x22``) is always IGMPv3,
        whatever its length.

        Args:
            type: The header's message type.
            max_resp_time: The header's max response time (the raw Max Resp
                Code octet; unused for a type whose version does not depend
                on it).
            length: The whole IGMP message's length, in octets.

        Returns:
            ``1``, ``2`` or ``3`` for that version, ``0`` for none of them.

        """
        if type == Enum_Type.IGMPv1_Membership_Report:
            return 1
        if type in (Enum_Type.IGMPv2_Membership_Report, Enum_Type.IGMPv2_Leave_Group):
            return 2
        if type == Enum_Type.IGMPv3_Membership_Report:
            return 3
        if type == Enum_Type.IGMP_Membership_Query:
            if length == 8:
                return 2 if max_resp_time else 1
            if length >= 12:
                return 3
            return 0
        return 0

    def _verify_checksum(self, igmp: '_PT', checksum: 'bytes', length: 'int') -> 'None':
        """Record on ``igmp`` the outcome of verifying the message's checksum.

        Only under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, as
        ``checksum_status``. Every version's checksum covers the whole message,
        the entire IP payload, with no pseudo-header (:rfc:`2236#section-2.3`,
        :rfc:`3376#section-4.1.2`, :rfc:`3376#section-4.2.2`). That holds for
        IGMPv1 as well: :rfc:`1112` defines an 8-octet message, and :rfc:`2236`,
        which updates it, sums a longer one whole (:rfc:`2236#section-2.5`). See
        :func:`~pcapkit.corekit.checksum.internet.verify_message`. A message the
        data ends inside, as its header's ``__short_read__`` records, is
        :attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.TRUNCATED`
        (:issue:`2689`).

        Args:
            igmp: Parsed message data.
            checksum: The checksum field, as on the wire.
            length: The whole message's length, in octets.

        """
        if config.CHECKSUM_VERIFY:
            from pcapkit.corekit.checksum.internet import (  # isort: skip # pylint: disable=import-outside-toplevel
                ChecksumStatus, verify_message)
            # NOTE: The checksum covers the whole message, so a message the data
            # ends inside leaves part of what it covers uncaptured (#2689).
            if '__short_read__' in self.__header__.__dict__:
                status = ChecksumStatus.TRUNCATED
            else:
                status = verify_message(self.alias, self._data, checksum, length=length)
            igmp.__update__([
                ('checksum_status', status),
            ])

    @classmethod
    def _dispatch(cls, data: 'bytes', length: 'int') -> 'Type[ProtocolBase] | Type[Raw]':
        """Pick the class that parses the IGMP message at the start of ``data``.

        The type and max response time are the first two octets, read here
        before any class is built, and :meth:`_classify` decides the version.

        Args:
            data: Payload of the IP layer, starting at the IGMP message.
            length: The IGMP message's length, in octets.

        Returns:
            :class:`~pcapkit.protocols.internet.igmpv1.IGMPv1`,
            :class:`~pcapkit.protocols.internet.igmpv2.IGMPv2` or
            :class:`~pcapkit.protocols.internet.igmpv3.IGMPv3` for the version
            the message classifies as; :class:`~pcapkit.protocols.misc.raw.Raw`
            for any other message, which then keeps its octets undissected.

        """
        from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel

        if len(data) < 2:
            return Raw
        version = cls._classify(data[0], data[1], length)
        return cls._member_of_version(version) if version else Raw

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[IGMP]':
        """The version class a ``version`` of ``1``, ``2`` or ``3`` names.

        Args:
            version: Version of IGMP, as :meth:`_classify` returns it or the
                ``version`` keyword gives it.

        Returns:
            :class:`~pcapkit.protocols.internet.igmpv1.IGMPv1`,
            :class:`~pcapkit.protocols.internet.igmpv2.IGMPv2` or
            :class:`~pcapkit.protocols.internet.igmpv3.IGMPv3`.

        Raises:
            ProtocolError: If ``version`` names none of them, or is no
                :obj:`int`: a :obj:`bool` or a :obj:`float` is refused even
                where it equals one.

        """
        from pcapkit.protocols.internet.igmpv1 import IGMPv1  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.igmpv2 import IGMPv2  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.igmpv3 import IGMPv3  # isort: skip # pylint: disable=import-outside-toplevel

        if isinstance(version, int) and not isinstance(version, bool):
            for number, member in ((1, IGMPv1), (2, IGMPv2), (3, IGMPv3)):
                if version == number:
                    return cast('Type[IGMP]', member)
        raise ProtocolError(f'IGMP: invalid version: {version!r}')
