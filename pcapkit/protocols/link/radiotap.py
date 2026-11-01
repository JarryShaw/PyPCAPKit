# -*- coding: utf-8 -*-
"""Radiotap - IEEE 802.11 Radiotap Header
============================================

.. module:: pcapkit.protocols.link.radiotap

:mod:`pcapkit.protocols.link.radiotap` contains
:class:`~pcapkit.protocols.link.radiotap.Radiotap` only, which implements the
extractor for the radiotap header [*]_ capture tools prepend to an 802.11
frame, as seen on a ``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture
whose ``arphrd_type`` is ``ARPHRD_IEEE80211_RADIOTAP`` --
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` dispatches here instead
of falling back to :class:`~pcapkit.protocols.misc.raw.Raw` for that one
case; see :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`.
Radiotap is not part of the 802.11 standard itself: it is a prefix *in front
of* the raw 802.11 MAC frame, written by the capturing tool rather than by
the radio. Its structure is a fixed 8-octet start, all little-endian:

.. table::

   ====== ==== =================== ================================
   Octets Bits Name                Description
   ====== ==== =================== ================================
   0      0    ``radiotap.it_version`` Header Revision (always ``0``)
   1      8    ``radiotap.it_pad``     Padding
   2      16   ``radiotap.it_len``     Header Length (header included)
   4      32   ``radiotap.it_present`` First Present-Flags Word
   ====== ==== =================== ================================

followed by a chain of further present-flags words -- bit 31 of a word
signals that another follows -- and then the optional-field region those
bitmasks select, each field aligned and sized per its own type. ``it_len``
bounds the whole of it; the 802.11 MAC frame starts at that offset.

Scope
-----

Decoding every optional field radiotap.org defines, and the 802.11 MAC frame
behind them, is future work tracked on :issue:`2460` and :issue:`2502` --
this is already the widest of that issue's five follow-ups, and the 802.11
MAC frame is a protocol family of its own (frame control, address fields
that vary in count with ToDS/FromDS, sequence control, optional QoS/HT
control, then a body that again dispatches by frame type/subtype). This
first cut instead:

* **Decodes** the fixed 8-octet start -- ``it_version``, ``it_pad``,
  ``it_len`` -- and walks the present-flags chain far enough to know how many
  words it has (:attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.present`),
  without decoding what any bit selects.
* **Skips, rather than decodes,** the optional-field region those bits
  select -- the octets between the present-flags chain and ``it_len`` are
  kept whole and undissected, as
  :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.fields`.
* **Leaves opaque** everything from ``it_len`` on: the 802.11 MAC frame
  itself, which has no dissector anywhere in this package yet. It is kept as
  :class:`~pcapkit.protocols.misc.raw.Raw` (or
  :class:`~pcapkit.protocols.misc.null.NoPayload` when nothing follows),
  unconditionally -- there is no next-layer dispatch table here, the same
  choice :class:`~pcapkit.protocols.link.netlink.Netlink` makes for its own
  per-family payloads.

.. [*] <https://www.radiotap.org/>; the Linux kernel's
   ``include/net/ieee80211_radiotap.h`` and ``net/wireless/radiotap.c``; and
   Wireshark's ``packet-ieee80211-radiotap.c``, all of which agree on the
   fixed start and the present-flags chaining described above.

.. versionadded:: 1.6.0

"""
import collections
from typing import TYPE_CHECKING

from pcapkit.const.linux.arphrd import ARPHRD as Enum_ARPHRD
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.link.radiotap import Radiotap as Data_Radiotap
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.link.radiotap import Radiotap as Schema_Radiotap
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, Sequence, Type

    from typing_extensions import Literal

__all__ = ['Radiotap']

#: Bit 31 of an ``it_present`` word: set, another present-flags word
#: follows; clear, the field-data region starts right after this word.
_IT_PRESENT_EXTENDED = 1 << 31

#: Octets of the fixed start every radiotap header has, before any extended
#: present-flags word or field data.
_FIXED_HEADER_LEN = 8

#: Octets of one present-flags word, extended or not.
_PRESENT_WORD_LEN = 4


class Radiotap(Link[Data_Radiotap, Schema_Radiotap],
              schema=Schema_Radiotap, data=Data_Radiotap):
    """This class implements the IEEE 802.11 radiotap header.

    The 802.11 MAC frame this header precedes has no dissector in this
    package; it is always kept as :class:`~pcapkit.protocols.misc.raw.Raw`
    (or :class:`~pcapkit.protocols.misc.null.NoPayload`), registered in
    :attr:`self.__proto__ <pcapkit.protocols.link.radiotap.Radiotap.__proto__>`
    only so :meth:`register` works the same way every other
    :class:`~pcapkit.protocols.link.link.Link` subclass's does -- see the
    module docstring's *Scope* section for what is, and is not, decoded.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer. Deliberately empty --
    #: see the class docstring -- so every key resolves through the
    #: :class:`~collections.defaultdict` fallback to
    #: :class:`~pcapkit.protocols.misc.raw.Raw`. Unused in practice, since
    #: :meth:`_import_next_layer` is overridden below and never consults it.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Radiotap"]':
        """Name of current protocol."""
        return 'Radiotap'

    @property
    def alias(self) -> 'Literal["Radiotap"]':
        """Acronym of corresponding protocol."""
        return 'Radiotap'

    @property
    def length(self) -> 'int':
        """Header length of current protocol.

        This is :attr:`self._info.it_len <pcapkit.protocols.data.link.radiotap.Radiotap.it_len>`
        exactly as captured, even when it disagrees with
        :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.present` and
        :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.fields` -- see
        :meth:`read`.

        """
        return self._info.it_len

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["Radiotap"]]':
        """Index ID of the protocol."""
        return ('Radiotap',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_Radiotap':  # pylint: disable=unused-argument
        """Read IEEE 802.11 radiotap header.

        Structure of the fixed start this class dissects, all little-endian:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   it_version  |    it_pad     |            it_len             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           it_present                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        followed, while the previous word's bit 31 is set, by a further
        ``it_present`` word, then by the field-data region those bits
        select (kept whole, see the module docstring's *Scope* section),
        then by the 802.11 MAC frame at offset ``it_len``.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        it_version = schema.it_version
        it_pad = schema.it_pad
        it_len = schema.it_len

        #: The octets after the fixed start: any extended present-flags
        #: words, the field-data region, and the 802.11 frame, all run
        #: together -- see :meth:`_import_next_layer` for how the frame is
        #: separated back out.
        rest = schema.payload

        present = [schema.it_present]
        offset = 0
        while present[-1] & _IT_PRESENT_EXTENDED:
            if offset + _PRESENT_WORD_LEN > len(rest):
                # Truncated mid present-flags chain, or a capture that never
                # supplies the word bit 31 promised -- stop rather than read
                # past what is actually here.
                break
            present.append(int.from_bytes(rest[offset:offset + _PRESENT_WORD_LEN], 'little'))
            offset += _PRESENT_WORD_LEN

        # ``it_len`` is supposed to bound the fixed start, the present-flags
        # chain and the field-data region together; clamp defensively
        # against a value that is smaller than the chain just walked
        # (internally inconsistent, but not a short *capture*) or larger
        # than what was actually captured (a short capture).
        tail_offset = max(it_len - _FIXED_HEADER_LEN, offset)
        tail_offset = min(tail_offset, len(rest))

        fields = rest[offset:tail_offset]
        #: int: Offset into :meth:`self._get_payload() <pcapkit.protocols.protocol.Protocol._get_payload>`
        #: where the 802.11 MAC frame starts -- read by
        #: :meth:`_import_next_layer`.
        self._mac_offset = tail_offset  # pylint: disable=attribute-defined-outside-init

        radiotap = Data_Radiotap(
            it_version=it_version,
            it_pad=it_pad,
            it_len=it_len,
            present=tuple(present),
            fields=fields,
        )
        header_len = _FIXED_HEADER_LEN + tail_offset
        return self._decode_next_layer(radiotap, 0, max(0, length - header_len))

    def make(self,
             it_version: 'int' = 0,
             it_pad: 'int' = 0,
             present: 'Sequence[int]' = (0,),
             fields: 'bytes' = b'',
             it_len: 'Optional[int]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_Radiotap':
        """Make (construct) packet data.

        Args:
            it_version: Header revision.
            it_pad: Padding octet.
            present: Every present-flags word, in order; the first is the
                mandatory one radiotap.org calls ``it_present``, and each
                but the last conventionally has bit 31 set (not enforced
                here, so a capture that read short of its own chain
                replays exactly: see the ``Note`` on
                :meth:`FRAD.make <pcapkit.protocols.link.frad.FRAD.make>`
                for the same tolerance).
            fields: The optional-field region ``present`` selects, kept
                whole; see the module docstring's *Scope* section.
            it_len: Total header length, header included; computed from
                ``present`` and ``fields`` when omitted.
            payload: Payload data (the 802.11 MAC frame, opaque to this
                class).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``it_version`` or ``it_pad`` does not fit in
                8 bits; if ``present`` is empty or any of its words does not
                fit in 32 bits; if ``fields`` is not :class:`bytes`; or if
                ``it_len`` is given and does not fit in 16 bits.

        """
        for name, value in (('it_version', it_version), ('it_pad', it_pad)):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFF:
                raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')

        present = tuple(present)
        if not present:
            raise ProtocolError(f'{self.alias}: invalid present: {present!r}, must not be empty')
        for word in present:
            if (not isinstance(word, int) or isinstance(word, bool)
                    or not 0 <= word <= 0xFFFF_FFFF):
                raise ProtocolError(f'{self.alias}: invalid present word: {word!r}')

        if not isinstance(fields, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid fields: {fields!r}, must be bytes')
        fields = bytes(fields)

        if isinstance(payload, ProtocolBase):
            payload_bytes = bytes(payload)
        elif isinstance(payload, Schema):
            payload_bytes = payload.pack()
        else:
            payload_bytes = bytes(payload)

        chain_bytes = b''.join(word.to_bytes(_PRESENT_WORD_LEN, 'little') for word in present[1:])

        if it_len is None:
            it_len = _FIXED_HEADER_LEN + len(chain_bytes) + len(fields)
        elif (not isinstance(it_len, int) or isinstance(it_len, bool)
              or not 0 <= it_len <= 0xFFFF):
            raise ProtocolError(f'{self.alias}: invalid it_len: {it_len!r}')

        return Schema_Radiotap(
            it_version=it_version,
            it_pad=it_pad,
            it_len=it_len,
            it_present=present[0],
            payload=chain_bytes + fields + payload_bytes,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object.

        The fixed start alone, ``8`` -- the shortest a radiotap header can
        structurally be (an empty present-flags word, no extended words, no
        field data). A capture shorter than this is not a radiotap header at
        all, so it is kept as :class:`~pcapkit.protocols.misc.raw.Raw`
        rather than parsed; see :meth:`Protocol._parse_next_layer
        <pcapkit.protocols.protocol.Protocol._parse_next_layer>`.

        """
        return 8

    @classmethod
    def __index__(cls) -> 'Enum_ARPHRD':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in Linux ARP hardware
            types, the ``arphrd_type`` that
            :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`
            dispatches here.

        """
        return Enum_ARPHRD.IEEE80211_RADIOTAP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Radiotap') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'it_version': data.it_version,
            'it_pad': data.it_pad,
            'present': data.present,
            'fields': data.fields,
            'it_len': data.it_len,
            'payload': cls._make_payload(data),
        }

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index -- unused, see below.
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack
                <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of next layer: always
            :class:`~pcapkit.protocols.misc.raw.Raw`, or
            :class:`~pcapkit.protocols.misc.null.NoPayload` when nothing
            follows -- the 802.11 MAC frame this header precedes has no
            dissector in this package; see the module docstring's *Scope*
            section. The only reason this overrides the base
            implementation is to start that payload at
            :attr:`self._mac_offset` rather than immediately after the
            fixed 8-octet start: everything in between -- the
            present-flags chain and the field-data region it selects --
            belongs to this header, not to the frame behind it, and
            :meth:`self._get_payload <pcapkit.protocols.protocol.Protocol._get_payload>`
            does not know that boundary on its own.

        """
        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'

        file_ = self._get_payload()
        offset = min(self._mac_offset, len(file_))
        file_ = file_[offset:]
        # NOTE: ``length``, as handed down from :meth:`read` through
        # :meth:`_decode_next_layer`, already counts only the octets beyond
        # the *whole* header (fixed start, present-flags chain and
        # field-data region) -- i.e. it is already relative to the start
        # ``file_`` is being trimmed to here, not to
        # :meth:`self._get_payload() <pcapkit.protocols.protocol.Protocol._get_payload>`'s
        # untrimmed start. Subtracting ``offset`` a second time would read
        # as though the chain and field-data region were being skipped
        # twice.
        if length is None:
            length = len(file_)
        else:
            length = max(0, min(length, len(file_)))

        if not min(length, len(file_)):
            from pcapkit.protocols.misc.null import \
                NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            from pcapkit.protocols.misc.raw import \
                Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel

        return self._parse_next_layer(protocol, file_, length, alias=proto, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      __context__=self._exctx)
