# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""LLC - Logical Link Control
================================

.. module:: pcapkit.protocols.link.llc.protocol

:mod:`pcapkit.protocols.link.llc.protocol` contains
:class:`~pcapkit.protocols.link.llc.protocol.LLC` only,
which implements the extractor for the IEEE 802.2 Logical Link
Control (LLC) [*]_ PDU of ISO/IEC 8802-2, whose structure is described as
below:

.. table::

   ====== ===== ================== =========================================
   Octets Bits  Name               Description
   ====== ===== ================== =========================================
   0          0 ``llc.dsap``       DSAP address, its low bit the I/G bit
   ------ ----- ------------------ -----------------------------------------
   1          8 ``llc.ssap``       SSAP address, less its low bit
   ------ ----- ------------------ -----------------------------------------
   1         15 ``llc.cr``         C/R bit, the low bit of the SSAP octet
   ------ ----- ------------------ -----------------------------------------
   2         16 ``llc.control``    Control field, one octet in the U format
                                   and two in the I and S formats
   ====== ===== ================== =========================================

.. [*] https://en.wikipedia.org/wiki/IEEE_802.2

"""
import collections
import types
from typing import TYPE_CHECKING

from pcapkit.const.llc.lsap import LSAP as Enum_LSAP
from pcapkit.const.llc.modifier_function import ModifierFunction as Enum_ModifierFunction
from pcapkit.const.llc.supervisory_function import SupervisoryFunction as Enum_SupervisoryFunction
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.llc.data import LLC as Data_LLC
from pcapkit.protocols.link.llc.data import Control as Data_Control
from pcapkit.protocols.link.llc.schema import LLC as Schema_LLC
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, ClassVar, DefaultDict, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['LLC']


class LLC(Link[Data_LLC, Schema_LLC],
          schema=Schema_LLC, data=Data_LLC):
    """This class implements IEEE 802.2 Logical Link Control.

    The PDU is dispatched from
    :class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet`, where its
    Length/Type field is a length, from
    :class:`~pcapkit.protocols.link.ieee802_11.protocol.IEEE802_11`, as the
    frame body of a data frame carrying an MSDU, and from
    :attr:`Frame.__proto__ <pcapkit.protocols.misc.pcap.frame.protocol.Frame.__proto__>`
    and :attr:`PCAPNG.__proto__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__proto__>`
    at ``LINKTYPE_ATM_RFC1483``.

    The control field is one octet in the U format, whose two low bits are
    ``11``, and two in the I format, whose low bit is ``0``, and the S format,
    whose two low bits are ``01``. The information field of an I PDU or a UI
    PDU is the next layer, dispatched by the DSAP through the protocols
    registered in the :attr:`self.__proto__ <pcapkit.protocols.link.llc.protocol.LLC.__proto__>`
    attribute. A DSAP :attr:`self.__paired__ <pcapkit.protocols.link.llc.protocol.LLC.__paired__>`
    flags is dispatched only when the SSAP, less its C/R bit, is the same
    address, as :rfc:`1042` sets both to the SNAP SAP:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
         - Paired
       * - :attr:`~pcapkit.const.llc.lsap.LSAP.SNAP`
         - :class:`pcapkit.protocols.link.snap.protocol.SNAP`
         - yes

    That of any other PDU, such as the XID or TEST information LLC exchanges
    itself, is kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

    .. versionadded:: 1.9.0

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, see
    #: :meth:`self._decode_next_layer
    #: <pcapkit.protocols.protocol.Protocol._decode_next_layer>` &
    #: :meth:`self._import_next_layer
    #: <pcapkit.protocols.protocol.Protocol._import_next_layer>`. Keyed by DSAP
    #: rather than by EtherType, so this class keeps a registry of its own
    #: instead of sharing :attr:`Link.__proto__
    #: <pcapkit.protocols.link.link.Link.__proto__>`; an entry is registered with
    #: :func:`~pcapkit.foundation.registry.protocols.link.register_lsap`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
        {
            Enum_LSAP.SNAP: ModuleDescriptor('pcapkit.protocols.link.snap.protocol', 'SNAP'),
        },
    )  # type: DefaultDict[int | Enum_LSAP, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: DSAP to paired flag mapping, read by :meth:`read`. A DSAP it flags is
    #: handed on only when the SSAP, less its C/R bit, is the same address, as
    #: the standard of the protocol at that DSAP fixes it, and one it does not
    #: hold is dispatched on alone. Written with the DSAP's entry in
    #: :attr:`__proto__` by :meth:`register`, through its ``paired`` keyword.
    __paired__ = {
        Enum_LSAP.SNAP: True,
    }  # type: dict[int | Enum_LSAP, bool]

    #: Read-only copy of :attr:`__paired__` as shipped, from which handing
    #: back the entry a DSAP shipped with restores its flag, see
    #: :meth:`register`.
    _shipped_paired = types.MappingProxyType(dict(__paired__))  # type: types.MappingProxyType[int | Enum_LSAP, bool]

    #: The enum the protocol map is keyed by, and that a bare int is no key,
    #: as :attr:`Link.__proto_key__ <pcapkit.protocols.link.link.Link.__proto_key__>`
    #: describes.
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_LSAP, False)

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Logical Link Control"]':
        """Name of current protocol."""
        return 'Logical Link Control'

    @property
    def length(self) -> 'Literal[3, 4]':
        """Header length of current protocol, the control field included."""
        return 3 if self._info.control.format == 'U' else 4

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_LLC':  # pylint: disable=unused-argument
        """Read IEEE 802.2 Logical Link Control.

        Structure of LLC PDU [IEEE Std 802.2]:

        .. code-block:: text

           +--------+--------+-------------+-----------------------+
           |  DSAP  |  SSAP  |   Control   |      Information      |
           |        |        |  8/16 bits  |                       |
           +--------+--------+-------------+-----------------------+

        Each field is transmitted least significant bit first, so the I/G
        bit of the DSAP, the C/R bit of the SSAP and the format bits of the
        control field are the low bits of their octets.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        control = schema.control
        control_ext = schema.control_ext or 0
        if not control & 0b1:
            ctrl = Data_Control(
                format='I',
                function=None,
                send_seq=control >> 1,
                recv_seq=control_ext >> 1,
                poll_final=bool(control_ext & 0b1),
                reserved=None,
            )
        elif not control & 0b10:
            ctrl = Data_Control(
                format='S',
                function=Enum_SupervisoryFunction.get(control & 0x0C),
                send_seq=None,
                recv_seq=control_ext >> 1,
                poll_final=bool(control_ext & 0b1),
                reserved=control >> 4,
            )
        else:
            ctrl = Data_Control(
                format='U',
                function=Enum_ModifierFunction.get(control & 0xEC),
                send_seq=None,
                recv_seq=None,
                poll_final=bool(control & 0x10),
                reserved=None,
            )

        llc = Data_LLC(
            dsap=schema.dsap,
            ssap=Enum_LSAP.get(schema.ssap & 0xFE),
            cr=bool(schema.ssap & 0b1),
            control=ctrl,
        )
        self._info = llc  # NOTE: :attr:`length` reads the data model.

        # NOTE: Only an I PDU and a UI PDU carry the service user's data; the information
        # field of an XID, TEST or FRMR PDU is LLC's own.
        user = ctrl.format == 'I' or (ctrl.format == 'U' and ctrl.function == Enum_ModifierFunction.UI)
        # NOTE: A DSAP whose standard fixes the SSAP too, as RFC 1042 does SNAP's, is handed
        # on only with that SSAP; a DSAP alone would decode more than the standard defines.
        paired = not self.__paired__.get(llc.dsap, False) or llc.ssap == llc.dsap
        return self._decode_next_layer(llc, schema.dsap if user and paired else -1, length - self.length)

    def make(self, *,
             dsap: 'Enum_LSAP | int' = Enum_LSAP.SNAP,
             ssap: 'Enum_LSAP | int' = Enum_LSAP.SNAP,
             cr: 'bool' = False,
             format: 'Literal["I", "S", "U"]' = 'U',  # pylint: disable=redefined-builtin
             function: 'Optional[Enum_SupervisoryFunction | Enum_ModifierFunction | int]' = None,
             send_seq: 'Optional[int]' = None,
             recv_seq: 'Optional[int]' = None,
             poll_final: 'bool' = False,
             reserved: 'Optional[int]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_LLC':
        """Make (construct) packet data.

        ``format`` decides which fields of the control field are carried. A
        field it carries and the caller leaves out is written as zeros, so
        ``function`` is :attr:`~pcapkit.const.llc.modifier_function.ModifierFunction.UI`
        in the U format and :attr:`~pcapkit.const.llc.supervisory_function.SupervisoryFunction.RR`
        in the S format; a field it does not carry must be left out.

        Args:
            dsap: DSAP address, its I/G bit included.
            ssap: SSAP address, an individual one.
            cr: C/R bit; :data:`True` for a response.
            format: Format of the control field.
            function: Supervisory function in the S format, or modifier
                function in the U format, as the first octet of the control
                field masked to its bits.
            send_seq: Send sequence number, N(S), in the I format.
            recv_seq: Receive sequence number, N(R), in the I and S formats.
            poll_final: Poll/final bit.
            reserved: Reserved bits 5 to 8 of the S format.
            payload: Payload data, the information field.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``dsap``, ``ssap`` or ``function`` is a name, or a
                code its field cannot carry; if ``ssap`` is a group address; if
                ``format`` is none of ``'I'``, ``'S'`` and ``'U'``; if a field is
                given that ``format`` does not carry; or if a value does not
                fit its field.

        """
        dsap_ = self._make_index(dsap, Enum_LSAP, bits=8, name='DSAP')
        ssap_ = self._make_index(ssap, Enum_LSAP, bits=8, name='SSAP')
        # NOTE: The low bit of the SSAP octet is the C/R bit, so the address itself is even.
        if ssap_ & 0b1:
            raise ProtocolError(f'{self.alias}: SSAP must be an individual address, not {int(ssap_):#04x}; '
                                'pass the C/R bit as cr')
        cr_ = self._make_uint(cr, bits=1, name='C/R bit')
        pf_ = self._make_uint(poll_final, bits=1, name='P/F bit')

        if format not in ('I', 'S', 'U'):
            raise ProtocolError(f'{self.alias}: invalid control field format: {format!r}')
        for name, given, carried in (('function', function, format != 'I'),
                                     ('send_seq', send_seq, format == 'I'),
                                     ('recv_seq', recv_seq, format != 'U'),
                                     ('reserved', reserved, format == 'S')):
            if given is not None and not carried:
                raise ProtocolError(f'{self.alias}: {name} given, but the {format} format carries none')

        recv = 0 if recv_seq is None else self._make_uint(recv_seq, bits=7, name='N(R)')
        control_ext = recv << 1 | pf_  # type: Optional[int]
        if format == 'I':
            send = 0 if send_seq is None else self._make_uint(send_seq, bits=7, name='N(S)')
            control = send << 1
        elif format == 'S':
            func = self._make_function(function, Enum_SupervisoryFunction, 0x0C)
            bits = 0 if reserved is None else self._make_uint(reserved, bits=4, name='reserved')
            control = 0b01 | func | bits << 4
        else:
            func = self._make_function(function, Enum_ModifierFunction, 0xEC)
            control, control_ext = 0b11 | func | pf_ << 4, None

        return Schema_LLC(
            dsap=dsap_,
            ssap=int(ssap_) | cr_,
            control=control,
            control_ext=control_ext,
            payload=payload,
        )

    @classmethod
    def register(cls, code: 'Enum_LSAP', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]', *,  # type: ignore[override]
                 paired: 'bool' = False) -> 'None':
        r"""Register a new protocol class for a DSAP.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

            The paired flag goes with the entry. Handing back the entry
            ``code`` shipped with, as a restore does, puts back the flag it
            shipped with too, so that an override and its restore leave
            :attr:`__paired__` as it was; any other entry takes ``paired``.

        Arguments:
            code: DSAP address
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
            paired: Whether a PDU to ``code`` is handed on only when its
                SSAP, less the C/R bit, is ``code`` too, as
                :attr:`__paired__` records it.

        Important:
            This overrides :meth:`Link.register
            <pcapkit.protocols.link.link.Link.register>` because
            :attr:`self.__proto__ <LLC.__proto__>` is keyed by DSAP rather than
            by EtherType (:issue:`2511`).

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this DSAP is already
                registered and the incumbent differs from the replacement; the
                message names both. See :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the guard,
                and for the shipped descriptor a restore puts back (:issue:`1504`).

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        stored = incumbent if entry is None else entry
        shipped = cls._shipped_proto.get(code)
        flag = cls._shipped_paired.get(code, False) if shipped is not None and stored is shipped else paired

        if entry is not None:
            if incumbent is not None and incumbent is not entry:
                warn(f'LSAP {code} already registered, overwriting '
                     f'{incumbent!r} with {entry!r}', RegistryWarning)
            cls.__proto__[code] = entry
        if flag:
            cls.__paired__[code] = True
        else:
            cls.__paired__.pop(code, None)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object.

        The longer form -- a two-octet control field, 4 octets -- per the
        reason ``L2TPv2.__length_hint__`` gives for a variable-length header.

        """
        return 4

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types, whose ``LINKTYPE_ATM_RFC1483`` packet begins with an
            LLC header.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.ATM_RFC1483  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_LLC') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        control = data.control
        return {
            'dsap': data.dsap,
            'ssap': data.ssap,
            'cr': data.cr,
            'format': control.format,
            'function': control.function,
            'send_seq': control.send_seq,
            'recv_seq': control.recv_seq,
            'poll_final': control.poll_final,
            'reserved': control.reserved,
            'payload': cls._make_payload(data),
        }

    def _make_function(self, function: 'Optional[Enum_SupervisoryFunction | Enum_ModifierFunction | int]',
                       namespace: 'Type[Enum_SupervisoryFunction] | Type[Enum_ModifierFunction]',
                       mask: 'int') -> 'int':
        """Make the function bits of an S-format or U-format control field.

        Args:
            function: Function, as the first octet of the control field masked
                to its bits; :data:`None` makes zeros.
            namespace: Enumeration of the format's functions.
            mask: Bits of the first octet the function takes.

        Returns:
            The function bits, in place in the first octet.

        Raises:
            ProtocolError: If ``function`` is a name, or a code with a bit
                outside ``mask`` set.

        """
        if function is None:
            return 0
        value = int(self._make_index(function, namespace, bits=8, name='function'))
        if value & ~mask:
            raise ProtocolError(f'{self.alias}: invalid {namespace.__name__}: {value:#04x} sets a bit '
                                f'outside {mask:#04x}')
        return value
