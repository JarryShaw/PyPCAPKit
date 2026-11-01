# -*- coding: utf-8 -*-
"""IEEE 802.11 - Wireless LAN MAC Header
===========================================

.. module:: pcapkit.protocols.link.ieee802_11

:mod:`pcapkit.protocols.link.ieee802_11` contains
:class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` only, which implements
the extractor for the IEEE 802.11 MAC header [*]_ of a protocol version 0
frame, as :class:`~pcapkit.protocols.link.radiotap.Radiotap` hands it on. Its
fields, in the order they appear, numeric ones little-endian:

.. table::

   ======================= ======= ============================================
   Name                    Octets  Present
   ======================= ======= ============================================
   ``frame_control``       2       always (§9.2.4.1)
   ``duration_id``         2       always (§9.2.4.2)
   ``addr1``               6       always (§9.2.4.3)
   ``addr2``               6       Management, Data, and Control frames that
                                   carry a TA (§9.2.4.3, §9.3.1)
   ``addr3``               6       Management and Data frames (§9.2.4.3)
   ``seq_ctrl``            2       Management and Data frames (§9.2.4.4)
   ``addr4``               6       Data frames with To DS and From DS set
                                   (§9.2.4.3)
   ``qos_control``         2       QoS Data subtypes (§9.2.4.5)
   ``ht_control``          4       QoS Data subtypes and Management frames
                                   with +HTC/Order set (§9.2.4.6)
   ======================= ======= ============================================

:func:`~pcapkit.protocols.schema.link.ieee802_11.layout` gives the rule per
frame type. A Control frame of a subtype whose layout this class does not
model, and an Extension frame, are read as the minimal frame format of
§9.2.3: the first three fields only. A Control Frame Extension frame and an
S1G Beacon lay out B8-B15 of Frame Control differently; see
:class:`~pcapkit.protocols.data.link.ieee802_11.FrameControl`.

The frame body (§9.2.4.7) follows the header and is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`, protected or not. So is the FCS
(§9.2.4.8) where one was captured: whether a capture carries it is a
radiotap Flags bit, which :class:`~pcapkit.protocols.link.radiotap.Radiotap`
does not decode, so the FCS stays at the end of the body. For the same reason,
the pad octets that radiotap's data-pad flag says follow the header stay at the
start of the body.

A frame of any protocol version but 0 is refused: version 1 is the PV1 frame
format of §9.8, whose Frame Control field is laid out differently, and
versions 2 and 3 are reserved.

.. [*] IEEE Std 802.11-2020, clause 9, *Frame formats*. The clause numbers
   above are its own, checked against Wireshark's ``packet-ieee80211.c`` where
   it cites one: §9.2.4.1.10, §9.2.4.6, §9.2.4.7 and §9.8.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.ieee802_11.control_subtype import ControlSubtype as Enum_ControlSubtype
from pcapkit.const.ieee802_11.data_subtype import DataSubtype as Enum_DataSubtype
from pcapkit.const.ieee802_11.extension_subtype import ExtensionSubtype as Enum_ExtensionSubtype
from pcapkit.const.ieee802_11.management_subtype import ManagementSubtype as Enum_ManagementSubtype
from pcapkit.const.ieee802_11.type import Type as Enum_Type
from pcapkit.protocols.data.link.ieee802_11 import IEEE802_11 as Data_IEEE802_11
from pcapkit.protocols.data.link.ieee802_11 import FrameControl as Data_FrameControl
from pcapkit.protocols.data.link.ieee802_11 import HTControl as Data_HTControl
from pcapkit.protocols.data.link.ieee802_11 import QoSControl as Data_QoSControl
from pcapkit.protocols.data.link.ieee802_11 import SequenceControl as Data_SequenceControl
from pcapkit.protocols.link.ethernet import PAT_MAC_ADDR
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.ieee802_11 import IEEE802_11 as Schema_IEEE802_11
from pcapkit.protocols.schema.link.ieee802_11 import Layout, layout
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Mapping, NoReturn, Optional, Type, Union

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

    Subtype = Union[Enum_ManagementSubtype, Enum_ControlSubtype, Enum_DataSubtype, Enum_ExtensionSubtype]

__all__ = ['IEEE802_11']

#: Subtype registry of each frame type (IEEE Std 802.11-2020, Table 9-1).
SUBTYPE = {
    Enum_Type.Management: Enum_ManagementSubtype,
    Enum_Type.Control: Enum_ControlSubtype,
    Enum_Type.Data: Enum_DataSubtype,
    Enum_Type.Extension: Enum_ExtensionSubtype,
}  # type: dict[int, Type[Subtype]]


def _header_length(fields: 'Layout') -> 'int':
    """Octets of a MAC header that carries ``fields`` after Address 1."""
    return (10 + 6 * fields.addr2 + 6 * fields.addr3 + 2 * fields.seq_ctrl
            + 6 * fields.addr4 + 2 * fields.qos_control + 4 * fields.ht_control)


class IEEE802_11(Link[Data_IEEE802_11, Schema_IEEE802_11],
                 schema=Schema_IEEE802_11, data=Data_IEEE802_11):
    """This class implements the IEEE 802.11 MAC header.

    The frame body is kept as :class:`~pcapkit.protocols.misc.raw.Raw`; see
    the module docstring.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["IEEE 802.11 Wireless LAN"]':
        """Name of current protocol."""
        return 'IEEE 802.11 Wireless LAN'

    @property
    def alias(self) -> 'Literal["802.11"]':
        """Acronym of corresponding protocol."""
        return '802.11'

    @property
    def length(self) -> 'int':
        """Header length of current protocol, from the fields its Frame Control declares."""
        info = self._info
        return _header_length(Layout(
            addr2=info.addr2 is not None,
            addr3=info.addr3 is not None,
            seq_ctrl=info.seq_ctrl is not None,
            addr4=info.addr4 is not None,
            qos_control=info.qos_control is not None,
            ht_control=info.ht_control is not None,
        ))

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IEEE802_11"]]':
        """Index ID of the protocol."""
        return ('IEEE802_11',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IEEE802_11':  # pylint: disable=unused-argument
        """Read IEEE 802.11 MAC header.

        Structure of the MAC header with every field present (IEEE Std
        802.11-2020 §9.2.3, *General frame format*), in octets:

        .. code-block:: text

           +-------+--------+------+------+------+------+------+-----+-----+------+-----+
           | Frame | Dura-  | Addr | Addr | Addr | Seq  | Addr | QoS | HT  | Body | FCS |
           | Ctrl  | tion/ID|  1   |  2   |  3   | Ctrl |  4   | Ctl | Ctl |      |     |
           +-------+--------+------+------+------+------+------+-----+-----+------+-----+
               2       2       6      6      6      2      6      2     4    var.    4

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the protocol version is not ``0``.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        frame_control = schema.frame_control
        if frame_control & 0b11:
            raise ProtocolError(f'{self.alias}: unsupported protocol version: {frame_control & 0b11}')

        ieee802_11 = Data_IEEE802_11(
            frame_control=self._read_frame_control(frame_control),
            duration_id=schema.duration_id,
            addr1=self._read_mac_addr(schema.addr1),
            addr2=None if schema.addr2 is None else self._read_mac_addr(schema.addr2),
            addr3=None if schema.addr3 is None else self._read_mac_addr(schema.addr3),
            seq_ctrl=None if schema.seq_ctrl is None else self._read_seq_ctrl(schema.seq_ctrl),
            addr4=None if schema.addr4 is None else self._read_mac_addr(schema.addr4),
            qos_control=None if schema.qos_control is None else self._read_qos_control(schema.qos_control),
            ht_control=None if schema.ht_control is None else self._read_ht_control(schema.ht_control),
        )
        hdr_len = _header_length(layout(frame_control))
        return self._decode_next_layer(ieee802_11, -1, max(0, length - hdr_len))

    def make(self,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.Data,  # pylint: disable=redefined-builtin
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             subtype: 'Subtype | StdlibEnum | AenumEnum | str | int' = 0,
             subtype_default: 'Optional[int]' = None,
             subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             subtype_reversed: 'bool' = False,
             version: 'Literal[0]' = 0,
             to_ds: 'Optional[bool]' = None,
             from_ds: 'Optional[bool]' = None,
             more_fragments: 'Optional[bool]' = None,
             retry: 'Optional[bool]' = None,
             control_frame_extension: 'Optional[int]' = None,
             power_management: 'Optional[bool]' = None,
             more_data: 'Optional[bool]' = None,
             protected: 'Optional[bool]' = None,
             order: 'Optional[bool]' = None,
             s1g_beacon_flags: 'Optional[int]' = None,
             duration_id: 'int' = 0,
             addr1: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             addr2: 'Optional[str | bytes | bytearray]' = None,
             addr3: 'Optional[str | bytes | bytearray]' = None,
             seq_ctrl: 'Optional[Data_SequenceControl | Mapping[str, int]]' = None,
             addr4: 'Optional[str | bytes | bytearray]' = None,
             qos_control: 'Optional[Data_QoSControl | Mapping[str, Any]]' = None,
             ht_control: 'Optional[int]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IEEE802_11':
        """Make (construct) packet data.

        The Frame Control subfields decide which fields the header carries,
        as :func:`~pcapkit.protocols.schema.link.ieee802_11.layout` reads them.
        A field the header carries and the caller leaves out is written as
        zeros; a field the header does not carry must be left out.

        Args:
            type: Type.
            type_default: Default value of ``type``.
            type_namespace: Namespace of ``type``.
            type_reversed: Reversed namespace of ``type``.
            subtype: Subtype; a name resolves against the registry ``type``
                selects unless ``subtype_namespace`` is given.
            subtype_default: Default value of ``subtype``.
            subtype_namespace: Namespace of ``subtype``.
            subtype_reversed: Reversed namespace of ``subtype``.
            version: Protocol Version; only ``0`` is built.
            to_ds: To DS.
            from_ds: From DS.
            more_fragments: More Fragments.
            retry: Retry.
            control_frame_extension: Control Frame Extension, which takes the
                four bits above in a Control Frame Extension frame and is
                refused in any other.
            power_management: Power Management.
            more_data: More Data.
            protected: Protected Frame.
            order: +HTC/Order.
            s1g_beacon_flags: B8-B15 of an S1G Beacon, which take the place of
                every flag above there and are refused in any other frame.
            duration_id: Duration/ID.
            addr1: Address 1.
            addr2: Address 2.
            addr3: Address 3.
            seq_ctrl: Sequence Control, a mapping of ``fragment_number`` and
                ``sequence_number``.
            addr4: Address 4.
            qos_control: QoS Control, a mapping of the keys
                :class:`~pcapkit.protocols.data.link.ieee802_11.QoSControl`
                has.
            ht_control: HT Control, the whole field as an integer.
            payload: Payload data: the frame body, and the FCS if any.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If a value does not fit its field, if ``version``
                is not ``0``, or if a field is given that the header does not
                carry.

        """
        type_ = self._make_index(type, type_default, namespace=type_namespace,
                                 reversed=type_reversed, pack=False)
        type_ = self._make_uint(type_, bits=2, name='type')
        subtype_ = self._make_index(subtype, subtype_default,
                                    namespace=subtype_namespace or SUBTYPE[Enum_Type(type_)],
                                    reversed=subtype_reversed, pack=False)
        subtype_ = self._make_uint(subtype_, bits=4, name='subtype')

        frame_control = self._make_frame_control(
            version=version, type=type_, subtype=subtype_,
            to_ds=to_ds, from_ds=from_ds, more_fragments=more_fragments, retry=retry,
            control_frame_extension=control_frame_extension,
            power_management=power_management, more_data=more_data,
            protected=protected, order=order, s1g_beacon_flags=s1g_beacon_flags,
        )
        fields = layout(frame_control)
        for name, given, carried in (('addr2', addr2, fields.addr2), ('addr3', addr3, fields.addr3),
                                     ('seq_ctrl', seq_ctrl, fields.seq_ctrl),
                                     ('addr4', addr4, fields.addr4),
                                     ('qos_control', qos_control, fields.qos_control),
                                     ('ht_control', ht_control, fields.ht_control)):
            if given is not None and not carried:
                raise ProtocolError(f'{self.alias}: {name} given, but this frame carries none')

        return Schema_IEEE802_11(
            frame_control=frame_control,
            duration_id=self._make_uint(duration_id, bits=16, name='duration_id'),
            addr1=self._make_mac_addr(addr1),
            addr2=self._make_mac_addr(addr2) if fields.addr2 else None,
            addr3=self._make_mac_addr(addr3) if fields.addr3 else None,
            seq_ctrl=self._make_seq_ctrl(seq_ctrl) if fields.seq_ctrl else None,
            addr4=self._make_mac_addr(addr4) if fields.addr4 else None,
            qos_control=self._make_qos_control(qos_control) if fields.qos_control else None,
            ht_control=self._make_ht_control(ht_control) if fields.ht_control else None,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[36]':
        """Return an estimated length for the object.

        The longest form -- every optional field present, 36 octets -- per
        the reason ``L2TPv2.__length_hint__`` gives for a variable-length
        header.

        """
        return 36

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol is reached only through
                :class:`~pcapkit.protocols.link.radiotap.Radiotap`'s payload
                dispatch, not through a link-layer header type of its own.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IEEE802_11') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        frame_control = data.frame_control
        return {
            'type': frame_control.type,
            'subtype': frame_control.subtype,
            'version': frame_control.version,
            'to_ds': frame_control.to_ds,
            'from_ds': frame_control.from_ds,
            'more_fragments': frame_control.more_fragments,
            'retry': frame_control.retry,
            'control_frame_extension': frame_control.control_frame_extension,
            'power_management': frame_control.power_management,
            'more_data': frame_control.more_data,
            'protected': frame_control.protected,
            'order': frame_control.order,
            's1g_beacon_flags': frame_control.s1g_beacon_flags,
            'duration_id': data.duration_id,
            'addr1': data.addr1,
            'addr2': data.addr2,
            'addr3': data.addr3,
            'seq_ctrl': data.seq_ctrl,
            'addr4': data.addr4,
            'qos_control': data.qos_control,
            'ht_control': None if data.ht_control is None else data.ht_control['value'],
            'payload': cls._make_payload(data),
        }

    def _read_frame_control(self, value: 'int') -> 'Data_FrameControl':
        """Read the Frame Control field (IEEE Std 802.11-2020 §9.2.4.1).

        In a Control Frame Extension frame, B8-B11 are the Control Frame
        Extension subfield rather than To DS, From DS, More Fragments and
        Retry (§9.2.4.1.1). In an S1G Beacon, B8-B15 are the subfields
        Wireshark's ``packet-ieee80211.c`` reads as ``wlan.fc.s1g.*``, so none
        of the eight flags is read there.

        Args:
            value: Frame Control field, as a little-endian integer.

        Returns:
            Parsed Frame Control field.

        """
        type_ = Enum_Type.get((value >> 2) & 0b11)
        subtype = SUBTYPE[type_].get((value >> 4) & 0b1111)
        extension = type_ == Enum_Type.Control and subtype == Enum_ControlSubtype.Control_Frame_Extension
        s1g_beacon = type_ == Enum_Type.Extension and subtype == Enum_ExtensionSubtype.S1G_Beacon
        low_flags = not (extension or s1g_beacon)

        return Data_FrameControl(
            version=value & 0b11,
            type=type_,
            subtype=subtype,
            to_ds=bool(value >> 8 & 1) if low_flags else None,
            from_ds=bool(value >> 9 & 1) if low_flags else None,
            more_fragments=bool(value >> 10 & 1) if low_flags else None,
            retry=bool(value >> 11 & 1) if low_flags else None,
            control_frame_extension=(value >> 8) & 0b1111 if extension else None,
            power_management=None if s1g_beacon else bool(value >> 12 & 1),
            more_data=None if s1g_beacon else bool(value >> 13 & 1),
            protected=None if s1g_beacon else bool(value >> 14 & 1),
            order=None if s1g_beacon else bool(value >> 15 & 1),
            s1g_beacon_flags=value >> 8 if s1g_beacon else None,
        )

    def _make_frame_control(self, *, version: 'int', type: 'int', subtype: 'int',  # pylint: disable=redefined-builtin
                            to_ds: 'Optional[bool]', from_ds: 'Optional[bool]',
                            more_fragments: 'Optional[bool]', retry: 'Optional[bool]',
                            control_frame_extension: 'Optional[int]',
                            power_management: 'Optional[bool]', more_data: 'Optional[bool]',
                            protected: 'Optional[bool]', order: 'Optional[bool]',
                            s1g_beacon_flags: 'Optional[int]') -> 'int':
        """Make the Frame Control field (IEEE Std 802.11-2020 §9.2.4.1).

        Args:
            version: Protocol Version.
            type: Type.
            subtype: Subtype.
            to_ds: To DS.
            from_ds: From DS.
            more_fragments: More Fragments.
            retry: Retry.
            control_frame_extension: Control Frame Extension.
            power_management: Power Management.
            more_data: More Data.
            protected: Protected Frame.
            order: +HTC/Order.
            s1g_beacon_flags: B8-B15 of an S1G Beacon.

        Returns:
            Frame Control field, as a little-endian integer.

        Raises:
            ProtocolError: If ``version`` is not ``0``; if a Control Frame
                Extension frame sets any of ``to_ds``, ``from_ds``,
                ``more_fragments`` and ``retry``, or an S1G Beacon sets any
                flag; if ``control_frame_extension`` or ``s1g_beacon_flags`` is
                given for a frame that does not carry it; or if a subfield does
                not fit.

        """
        if not isinstance(version, int) or isinstance(version, bool) or version:
            raise ProtocolError(f'{self.alias}: unsupported protocol version: {version!r}')

        flags = {'to_ds': to_ds, 'from_ds': from_ds, 'more_fragments': more_fragments, 'retry': retry}
        high_flags = {'power_management': power_management, 'more_data': more_data,
                      'protected': protected, 'order': order}
        if type == Enum_Type.Extension and subtype == Enum_ExtensionSubtype.S1G_Beacon:
            for name, flag in {**flags, **high_flags}.items():
                if flag:
                    raise ProtocolError(f'{self.alias}: {name} set in an S1G Beacon')
            if control_frame_extension is not None:
                raise ProtocolError(f'{self.alias}: control_frame_extension given, but this '
                                    'frame is not a Control Frame Extension frame')
            byte = self._make_uint(s1g_beacon_flags or 0, bits=8, name='s1g_beacon_flags')
            return version | type << 2 | subtype << 4 | byte << 8
        if s1g_beacon_flags is not None:
            raise ProtocolError(f'{self.alias}: s1g_beacon_flags given, but this frame is not '
                                'an S1G Beacon')

        if type == Enum_Type.Control and subtype == Enum_ControlSubtype.Control_Frame_Extension:
            for name, flag in flags.items():
                if flag:
                    raise ProtocolError(f'{self.alias}: {name} set in a Control Frame Extension frame')
            low = self._make_uint(control_frame_extension or 0, bits=4, name='control_frame_extension')
        else:
            if control_frame_extension is not None:
                raise ProtocolError(f'{self.alias}: control_frame_extension given, but this '
                                    'frame is not a Control Frame Extension frame')
            low = 0
            for shift, (name, flag) in enumerate(flags.items()):
                low |= self._make_uint(False if flag is None else flag, bits=1, name=name) << shift

        high = 0
        for shift, (name, flag) in enumerate(high_flags.items()):
            high |= self._make_uint(False if flag is None else flag, bits=1, name=name) << shift

        return version | type << 2 | subtype << 4 | low << 8 | high << 12

    def _read_mac_addr(self, addr: 'bytes') -> 'str':
        """Read MAC address.

        Args:
            addr: MAC address.

        Returns:
            Colon (``:``) separated *hex* encoded MAC address.

        """
        return addr.hex(':')

    def _make_mac_addr(self, addr: 'Optional[str | bytes | bytearray]') -> 'bytes':
        """Make MAC address.

        Args:
            addr: MAC address; :obj:`None` makes all zeros.

        Returns:
            MAC address packed as 6 octets.

        Raises:
            ProtocolError: If ``addr`` is not a ``:``- or ``-``-separated *hex*
                encoded MAC address.

        """
        if addr is None:
            return bytes(6)
        if not isinstance(addr, (str, bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid MAC address: must be a str, bytes or '
                                f'bytearray, not {addr!r}')
        _addr = addr.encode() if isinstance(addr, str) else bytes(addr)

        if PAT_MAC_ADDR.fullmatch(_addr) is not None:
            return bytes.fromhex(_addr.replace(b':', b'').replace(b'-', b'').decode())
        raise ProtocolError(f'{self.alias}: invalid MAC address: {addr!r}')

    def _read_seq_ctrl(self, value: 'int') -> 'Data_SequenceControl':
        """Read the Sequence Control field (IEEE Std 802.11-2020 §9.2.4.4).

        Args:
            value: Sequence Control field, as a little-endian integer.

        Returns:
            Parsed Sequence Control field.

        """
        return Data_SequenceControl(
            fragment_number=value & 0b1111,
            sequence_number=value >> 4,
        )

    def _make_seq_ctrl(self, seq_ctrl: 'Optional[Data_SequenceControl | Mapping[str, int]]') -> 'int':
        """Make the Sequence Control field (IEEE Std 802.11-2020 §9.2.4.4).

        Args:
            seq_ctrl: Sequence Control field; :obj:`None` makes zeros.

        Returns:
            Sequence Control field, as a little-endian integer.

        Raises:
            ProtocolError: If a subfield does not fit.

        """
        if seq_ctrl is None:
            return 0
        fragment_number = self._make_uint(seq_ctrl['fragment_number'], bits=4, name='fragment_number')
        sequence_number = self._make_uint(seq_ctrl['sequence_number'], bits=12, name='sequence_number')
        return fragment_number | sequence_number << 4

    def _read_qos_control(self, value: 'int') -> 'Data_QoSControl':
        """Read the QoS Control field (IEEE Std 802.11-2020 §9.2.4.5).

        Args:
            value: QoS Control field, as a little-endian integer.

        Returns:
            Parsed QoS Control field.

        """
        return Data_QoSControl(
            tid=value & 0b1111,
            eosp=bool(value >> 4 & 1),
            ack_policy=(value >> 5) & 0b11,
            amsdu_present=bool(value >> 7 & 1),
            bits_8_15=value >> 8,
        )

    def _make_qos_control(self, qos_control: 'Optional[Data_QoSControl | Mapping[str, Any]]') -> 'int':
        """Make the QoS Control field (IEEE Std 802.11-2020 §9.2.4.5).

        Args:
            qos_control: QoS Control field; :obj:`None` makes zeros.

        Returns:
            QoS Control field, as a little-endian integer.

        Raises:
            ProtocolError: If a subfield does not fit.

        """
        if qos_control is None:
            return 0
        return (self._make_uint(qos_control['tid'], bits=4, name='tid')
                | self._make_uint(qos_control['eosp'], bits=1, name='eosp') << 4
                | self._make_uint(qos_control['ack_policy'], bits=2, name='ack_policy') << 5
                | self._make_uint(qos_control['amsdu_present'], bits=1, name='amsdu_present') << 7
                | self._make_uint(qos_control['bits_8_15'], bits=8, name='bits_8_15') << 8)

    def _read_ht_control(self, value: 'int') -> 'Data_HTControl':
        """Read the HT Control field (IEEE Std 802.11-2020 §9.2.4.6).

        Args:
            value: HT Control field, as a little-endian integer.

        Returns:
            Parsed HT Control field.

        """
        if not value & 0b1:
            variant = 'HT'  # type: Literal['HT', 'VHT', 'HE']
        elif not value & 0b10:
            variant = 'VHT'
        else:
            variant = 'HE'
        return Data_HTControl(variant=variant, value=value)

    def _make_ht_control(self, value: 'Optional[int]') -> 'int':
        """Make the HT Control field (IEEE Std 802.11-2020 §9.2.4.6).

        Args:
            value: HT Control field, as an integer; :obj:`None` makes zeros.

        Returns:
            HT Control field, as a little-endian integer.

        Raises:
            ProtocolError: If ``value`` does not fit in 32 bits.

        """
        if value is None:
            return 0
        return self._make_uint(value, bits=32, name='ht_control')
