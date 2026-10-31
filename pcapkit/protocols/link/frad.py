# -*- coding: utf-8 -*-
"""FRAD - Frame Relay Access Device
======================================

.. module:: pcapkit.protocols.link.frad

:mod:`pcapkit.protocols.link.frad` contains
:class:`~pcapkit.protocols.link.frad.FRAD` only, which implements the
extractor for Frame Relay's multiprotocol encapsulation [*]_, as seen on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_FRAD`` -- :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`
dispatches here instead of falling back to
:class:`~pcapkit.protocols.misc.raw.Raw` for that one case; see
:data:`~pcapkit.protocols.link.linux_sll._ARPHRD_NOT_ETHERTYPE`. Its
structure is the Q.922 LAPF address onward, with no trailing FCS: a 2-octet
``frad.addr``, a 1-octet ``frad.control`` (``0x03``, UI, for ordinary data
traffic), then a 1-octet ``frad.nlpid`` -- or, when SNAP-encapsulated, the
``0x00`` pad RFC 2427 writes in its place, followed by the real NLPID
(``0x80``) and a 5-octet SNAP header (OUI and PID). See
:meth:`FRAD.read <pcapkit.protocols.link.frad.FRAD.read>` for the full byte
diagram and :mod:`pcapkit.protocols.schema.link.frad` for the field-by-field
schema.

.. [*] :rfc:`2427` (obsoleting :rfc:`1490`)

.. versionadded:: 1.6.0

"""
import collections
from typing import TYPE_CHECKING

from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.link.frad import FRAD as Data_FRAD
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.frad import FRAD as Schema_FRAD
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, DefaultDict, NoReturn, Optional, Type

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['FRAD']


class FRAD(Link[Data_FRAD, Schema_FRAD],
          schema=Schema_FRAD, data=Data_FRAD):
    """This class implements Frame Relay Access Device (FRAD) frames.

    A frame whose NLPID (after resolving the ``0x00`` pad RFC 2427 writes
    ahead of a SNAP header) is ``0xCC`` or ``0x8E`` dispatches to
    :class:`~pcapkit.protocols.internet.ipv4.IPv4` or
    :class:`~pcapkit.protocols.internet.ipv6.IPv6` respectively, registered
    in the :attr:`self.__proto__ <pcapkit.protocols.link.frad.FRAD.__proto__>`
    attribute. A SNAP header whose OUI is ``00-00-00`` carries an EtherType
    in its PID, resolved instead through the family registry every
    Ethernet/VLAN/LinuxSLL frame shares,
    :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>` --
    which is how an ARP frame (PID ``0x0806``) over Frame Relay is reached.
    Every other NLPID (Q.933 signalling, ISO CLNP/ES-IS/IS-IS, FRF.9/FRF.12
    compression and fragmentation, PPP-in-Frame-Relay, and a SNAP header
    whose OUI names a bridged medium rather than an EtherType) is kept as
    :class:`~pcapkit.protocols.misc.raw.Raw`, exactly as every ``arphrd_type``
    this module's docstring lists already was before this class existed.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, keyed by the resolved
    #: NLPID rather than by EtherType, so this class keeps a registry of its
    #: own instead of sharing :attr:`Link.__proto__
    #: <pcapkit.protocols.link.link.Link.__proto__>` -- the same reason
    #: :class:`~pcapkit.protocols.link.loopback.Loopback` keeps one of its own.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            0xCC: ModuleDescriptor('pcapkit.protocols.internet.ipv4', 'IPv4'),
            0x8E: ModuleDescriptor('pcapkit.protocols.internet.ipv6', 'IPv6'),
        },
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Frame Relay Access Device"]':
        """Name of current protocol."""
        return 'Frame Relay Access Device'

    @property
    def alias(self) -> 'Literal["FRAD"]':
        """Acronym of corresponding protocol."""
        return 'FRAD'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.len

    @property
    def protocol(self) -> 'int':  # type: ignore[override]
        """NLPID of next layer protocol."""
        return self._info.nlpid

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["FRAD"]]':
        """Index ID of the protocol."""
        return ('FRAD',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_FRAD':  # pylint: disable=unused-argument
        """Read Frame Relay Access Device (FRAD) frame.

        Structure of a direct-NLPID ``FRAD`` frame, the common case:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      DLCI (high)     |C/R|EA0|  DLCI (low)   |FECN|BECN|DE|EA1|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |            Control            |             NLPID             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        A SNAP-encapsulated frame inserts a ``0x00`` pad and a ``0x80`` NLPID
        in place of the single NLPID octet above, followed by a 3-octet OUI
        and a 2-octet PID (:rfc:`2427#section-4.1`).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        addr = schema.addr
        _dlci = (addr['dlci_hi'] << 4) | addr['dlci_lo']

        _raw_nlpid = schema.nlpid
        if not _raw_nlpid:
            _ext = schema.ext_nlpid
            _nlpid = _ext if isinstance(_ext, int) else 0
            _hdr_len = 5
        else:
            _nlpid = _raw_nlpid
            _hdr_len = 4

        _snap_oui = None  # type: Optional[bytes]
        _snap_pid = None  # type: Optional[int]
        self._snap_ethertype = None  # type: Optional[int] # pylint: disable=attribute-defined-outside-init
        if _nlpid == 0x80:
            _snap_oui = schema.oui
            _snap_pid = schema.pid
            _hdr_len += 5
            if _snap_oui == b'\x00\x00\x00' and isinstance(_snap_pid, int):
                self._snap_ethertype = _snap_pid  # pylint: disable=attribute-defined-outside-init

        frad = Data_FRAD(
            dlci=_dlci,
            cr=addr['cr'],
            fecn=addr['fecn'],
            becn=addr['becn'],
            de=addr['de'],
            control=schema.control,
            nlpid=_nlpid,
            snap_oui=_snap_oui,
            snap_pid=_snap_pid,
            len=_hdr_len,
        )
        return self._decode_next_layer(frad, _nlpid, length - _hdr_len)

    def make(self,
             dlci: 'int' = 0,
             cr: 'int' = 0,
             fecn: 'int' = 0,
             becn: 'int' = 0,
             de: 'int' = 0,
             control: 'int' = 0x03,
             nlpid: 'int' = 0xCC,
             snap_oui: 'Optional[bytes]' = None,
             snap_pid: 'Optional[int]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_FRAD':
        """Make (construct) packet data.

        Args:
            dlci: Data Link Connection Identifier, 10 bits (``0`` to ``1023``).
            cr: Command/response indication bit.
            fecn: Forward explicit congestion notification bit.
            becn: Backward explicit congestion notification bit.
            de: Discard eligibility bit.
            control: Control field; ``0x03`` (UI) for ordinary data traffic.
            nlpid: NLPID selecting the encapsulated protocol; ``0xCC`` for
                IPv4, ``0x8E`` for IPv6, ``0x80`` for a SNAP header.
            snap_oui: SNAP OUI; required, and only meaningful, when ``nlpid``
                is ``0x80``.
            snap_pid: SNAP PID; required, and only meaningful, when ``nlpid``
                is ``0x80``.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``dlci`` does not fit in 10 bits; if ``cr``,
                ``fecn``, ``becn`` or ``de`` is not ``0`` or ``1``; if
                ``control`` or ``nlpid`` does not fit in 8 bits; if ``nlpid``
                is ``0x80`` and ``snap_oui`` is not exactly 3 octets or
                ``snap_pid`` does not fit in 16 bits; or if either
                ``snap_oui`` or ``snap_pid`` is given while ``nlpid`` is not
                ``0x80``.

        Note:
            ``nlpid`` is not refused for being ``0`` -- the SNAP pad marker,
            never a value of its own on the wire -- even though no caller
            building a frame from scratch should pass it: :meth:`from_data
            <pcapkit.protocols.link.link.Link.from_data>` replays a capture
            that ended inside the header through this same method, and a
            capture cut short of the ``nlpid`` octet reads as ``0`` (zero
            rather than missing). Rejecting it here would make a short
            capture fail to rebuild, the one invariant every protocol in
            this package keeps (:issue:`1458`).

        """
        if not isinstance(dlci, int) or isinstance(dlci, bool) or not 0 <= dlci <= 0x3FF:
            raise ProtocolError(f'{self.alias}: invalid DLCI: {dlci!r}')
        for name, bit in (('cr', cr), ('fecn', fecn), ('becn', becn), ('de', de)):
            if bit not in (0, 1):
                raise ProtocolError(f'{self.alias}: invalid {name}: {bit!r}, must be 0 or 1')
        if not isinstance(control, int) or isinstance(control, bool) or not 0 <= control <= 0xFF:
            raise ProtocolError(f'{self.alias}: invalid control: {control!r}')
        if not isinstance(nlpid, int) or isinstance(nlpid, bool) or not 0 <= nlpid <= 0xFF:
            raise ProtocolError(f'{self.alias}: invalid nlpid: {nlpid!r}')

        if nlpid == 0x80:
            if not isinstance(snap_oui, (bytes, bytearray)) or len(snap_oui) != 3:
                raise ProtocolError(f'{self.alias}: invalid snap_oui: {snap_oui!r}, '
                                    f'must be exactly 3 octets when nlpid is 0x80')
            if (not isinstance(snap_pid, int) or isinstance(snap_pid, bool)
                    or not 0 <= snap_pid <= 0xFFFF):
                raise ProtocolError(f'{self.alias}: invalid snap_pid: {snap_pid!r}, '
                                    f'must fit in 16 bits when nlpid is 0x80')
            _schema_nlpid, _ext_nlpid = 0, 0x80
            _oui, _pid = bytes(snap_oui), snap_pid
        else:
            if snap_oui is not None or snap_pid is not None:
                raise ProtocolError(f'{self.alias}: snap_oui and snap_pid are only meaningful '
                                    f'when nlpid is 0x80, not {nlpid!r}')
            _schema_nlpid, _ext_nlpid = nlpid, None
            _oui, _pid = None, None

        return Schema_FRAD(
            addr={
                'dlci_hi': dlci >> 4,
                'cr': cr,
                'ea1': 0,
                'dlci_lo': dlci & 0xF,
                'fecn': fecn,
                'becn': becn,
                'de': de,
                'ea2': 1,
            },
            control=control,
            nlpid=_schema_nlpid,
            ext_nlpid=_ext_nlpid,
            oui=_oui,
            pid=_pid,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[10]':
        """Return an estimated length for the object.

        The longest form -- a SNAP-encapsulated header, 10 octets -- per the
        reason :meth:`L2TPv2.__length_hint__
        <pcapkit.protocols.link.l2tpv2.L2TPv2.__length_hint__>` gives for a
        variable-length header: the shortest form would reject a fully
        captured longer header as too short.

        """
        return 10

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol is reached only through
                :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`'s
                ``arphrd_type`` dispatch, not through a link-layer header
                type of its own.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_FRAD') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'dlci': data.dlci,
            'cr': data.cr,
            'fecn': data.fecn,
            'becn': data.becn,
            'de': data.de,
            'control': data.control,
            'nlpid': data.nlpid,
            'snap_oui': data.snap_oui,
            'snap_pid': data.snap_pid,
            'payload': cls._make_payload(data),
        }

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index -- the resolved NLPID, unused
                when a SNAP EtherType was recorded by :meth:`read`.
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack
                <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of next layer. A SNAP header whose OUI is ``00-00-00``
            is dispatched through :attr:`Link.__proto__
            <pcapkit.protocols.link.link.Link.__proto__>` instead of
            :attr:`self.__proto__ <pcapkit.protocols.link.frad.FRAD.__proto__>`,
            keyed by the PID as an EtherType -- see :meth:`read`, which
            records it as ``self._snap_ethertype``.

        """
        ethertype = getattr(self, '_snap_ethertype', None)
        if ethertype is None:
            return super()._import_next_layer(proto, length, packet=packet)  # type: ignore[misc,call-arg]

        file_ = self._get_payload()
        if length is None:
            length = len(file_)

        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'
        if not min(length, len(file_)):
            from pcapkit.protocols.misc.null import \
                NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import \
                Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self._lookup_next_layer(Link.__proto__, ethertype)

        return self._parse_next_layer(protocol, file_, length, alias=ethertype, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      __context__=self._exctx)
