# -*- coding: utf-8 -*-
"""IGMP - Internet Group Management Protocol
================================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` contains
:class:`~pcapkit.protocols.internet.igmp.IGMP`, the abstract base of
IGMPv1 (:rfc:`1112`), IGMPv2 (:rfc:`2236`) and IGMPv3 (:rfc:`3376`) messages.
IGMPv1 and IGMPv2 share one 8-octet layout, so the base holds that shared
schema, data model and read path. :class:`~pcapkit.protocols.internet.igmpv1.IGMP`,
:class:`~pcapkit.protocols.internet.igmpv2.IGMP` and
:class:`~pcapkit.protocols.internet.igmpv3.IGMP` set :attr:`version`; IGMPv3's
wire format differs materially (a Query's source-list extension, a Report's
group-record list), so it carries its own schema and data model instead. The
registry entry for IP protocol 2 is this base, and :meth:`IGMP._dispatch
<pcapkit.protocols.internet.igmp.IGMP._dispatch>` picks the version class.

.. versionadded:: 1.6.0

   IGMPv1 (:rfc:`1112`) and IGMPv2 (:rfc:`2236`) (:issue:`2439`).

.. versionadded:: 1.6.0

   IGMPv3 (:rfc:`3376`) (:issue:`2448`).

"""

import abc
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.igmp.type import Type as Enum_Type
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.igmp import IGMP as Data_IGMP
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.protocols.schema.internet.igmp import IGMP as Schema_IGMP
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address
    from typing import Any, Literal, Optional, Type

    from aenum import IntEnum as AenumEnum

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IGMP']


class IGMP(Internet[_PT, _ST], Generic[_PT, _ST],
           schema=Schema_IGMP, data=Data_IGMP):
    """This class implements Internet Group Management Protocol.

    The class is abstract: :attr:`version` is set by the concrete IGMPv1,
    IGMPv2 and IGMPv3 classes. :meth:`read` refuses a message that
    :meth:`_classify` does not place in :attr:`version`.

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
        """Acronym of corresponding protocol, ``'IGMPv1'``, ``'IGMPv2'`` or ``'IGMPv3'``."""
        return f'IGMPv{self.version}'

    @property
    def length(self) -> 'Literal[8]':
        """Header length of current protocol."""
        return 8

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IGMP"], Literal["IGMPv1"], Literal["IGMPv2"], Literal["IGMPv3"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, the family name and all three
            versions; the concrete IGMPv1, IGMPv2 and IGMPv3 classes narrow
            it to their own version.

        """
        return ('IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3')

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
            raise ProtocolError(f'{self.alias}: {schema.type!r} is not an {self.alias} '
                                f'message ({length} octets)')

        igmp = Data_IGMP(
            type=schema.type,
            max_resp_time=schema.max_resp_time,
            checksum=schema.checksum,
            group=schema.group,
        )
        # NOTE: IGMPv1/v2 has no next-protocol field, so trailing octets stay
        # as ``Raw``.
        return self._decode_next_layer(cast('_PT', igmp), None, length - self.length)

    def make(self,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.IGMP_Membership_Query,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             max_resp_time: 'int' = 0,
             checksum: 'bytes' = b'\x00\x00',
             group: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        The version of a constructed message is decided by its ``type``,
        ``max_resp_time`` and length (see :meth:`_classify`), not by the class
        that built it.

        Args:
            type: Message type.
            type_default: Default value of message type.
            type_namespace: Namespace of message type.
            type_reversed: If the namespace is reversed.
            max_resp_time: Max response time, in tenths of a second; zero for
                an IGMPv1 message.
            checksum: Checksum over the message with this field zeroed, no
                pseudo-header (:rfc:`2236#section-2.3`).
            group: Group address; ``0.0.0.0`` for a General Query.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is outside 0 to 255, or ``max_resp_time``
                is not a non-:obj:`bool` integer from 0 to 255.

        """
        type_value = self._make_index(type, type_default, namespace=type_namespace,
                                      reversed=type_reversed, pack=False)
        for name, value in (('type', type_value), ('max_resp_time', max_resp_time)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
                raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')

        return Schema_IGMP(
            type=type_value,  # type: ignore[arg-type]
            max_resp_time=max_resp_time,
            checksum=checksum,
            group=group,
            payload=payload,
        )  # type: ignore[return-value]

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

    @classmethod
    def _dispatch(cls, data: 'bytes', length: 'int') -> 'Type[ProtocolBase] | Type[Raw]':
        """Pick the class that parses the IGMP message at the start of ``data``.

        The type and max response time are the first two octets, read here
        before any class is built, and :meth:`_classify` decides the version.

        Args:
            data: Payload of the IP layer, starting at the IGMP message.
            length: The IGMP message's length, in octets.

        Returns:
            :class:`~pcapkit.protocols.internet.igmpv1.IGMP`,
            :class:`~pcapkit.protocols.internet.igmpv2.IGMP` or
            :class:`~pcapkit.protocols.internet.igmpv3.IGMP` for the version
            the message classifies as; :class:`~pcapkit.protocols.misc.raw.Raw`
            for any other message, which then keeps its octets undissected.

        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel

        if len(data) < 2:
            return Raw
        version = cls._classify(data[0], data[1], length)
        return {1: IGMPv1, 2: IGMPv2, 3: IGMPv3}.get(version, Raw)
