# -*- coding: utf-8 -*-
"""Radiotap - IEEE 802.11 Radiotap Header
============================================

.. module:: pcapkit.protocols.link.radiotap

:mod:`pcapkit.protocols.link.radiotap` contains
:class:`~pcapkit.protocols.link.radiotap.Radiotap` only, which implements the
extractor for the radiotap header [*]_ capture tools prepend to an 802.11
frame, as seen on a ``LINKTYPE_IEEE802_11_RADIOTAP`` capture, or on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_IEEE80211_RADIOTAP``.
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` and
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` bind
:attr:`LinkType.IEEE802_11_RADIOTAP <pcapkit.const.reg.linktype.LinkType.IEEE802_11_RADIOTAP>`
here, and :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` dispatches here
for that one ``arphrd_type`` instead of falling back to
:class:`~pcapkit.protocols.misc.raw.Raw`; see
:attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`.
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

This class:

* **Decodes** the fixed 8-octet start -- ``it_version``, ``it_pad``,
  ``it_len`` -- and walks the present-flags chain, recording every word as
  :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.present`.
* **Keeps** the optional-field region those bits select whole, as
  :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.fields`, which is
  what a rebuild from the data model writes, and **decodes** it as
  :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.decoded`, by the
  rules below.
* **Hands** everything from ``it_len`` on, the 802.11 MAC frame, to
  :class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11`
  (:class:`~pcapkit.protocols.misc.no_payload.NoPayload` when nothing follows).
  The header names no next protocol, since an 802.11 frame always follows it,
  so the frame is looked up in
  :attr:`Radiotap.__proto__ <pcapkit.protocols.link.radiotap.Radiotap.__proto__>`
  under :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`.

Field Decoding
--------------

The bits are walked in order, word by word, and the fields they select follow
one another in the same order, each aligned to its own boundary counted from
the start of the header. A field type is read and made by the methods
:attr:`Radiotap.__field__ <pcapkit.protocols.link.radiotap.Radiotap.__field__>`
names for it, through the schema the
:class:`~pcapkit.protocols.schema.link.radiotap.RadiotapField` registry holds
for it: the schema's fields are the subfields of the type's page on
radiotap.org, their total is its size, and its ``__align__`` its alignment,
which match the tables of the Linux kernel, Wireshark and radiotap.org's own
``radiotap-library`` wherever they size it. A page that names no alignment
takes that of its subfields, single octets, but for FHSS, which those three
align to 2. The fields are radiotap.org's defined ones, and RTS retries and data
retries, bits 16 and 17, from its unofficially used ones, which those three
size alike; OpenBSD writes a 2-octet RSSI field at bit 16 instead, which is not
read. A bitmap radiotap.org defines bit by bit is a member of its flag registry
under :mod:`pcapkit.const.radiotap`, which keeps the bits it does not name. A
bitmap that mixes value subfields with known bits -- the MCS ``flags``, the HE
``data1`` and ``data2``, the HE-MU ``flags1`` and ``flags2`` and the U-SIG
``common`` -- is split: each value subfield is an integer, and its other bits,
the undefined ones among them, a member of its known-bits registry. A field
type registered through
:func:`~pcapkit.foundation.registry.protocols.link.register_radiotap_field` is
decoded the same way.

* **Namespaces.** Bits 29 and 30 mean the same in every word. Bit 29, the
  Radiotap Namespace field, carries nothing, and the next word restarts the
  radiotap namespace at bit 0. Bit 30, the Vendor Namespace field, carries an
  OUI, a sub-namespace and a ``skip_length``; the words up to the next
  namespace field select vendor fields, whose data is the ``skip_length``
  octets after it, kept whole. Without either, the next word continues the
  namespace, each bit numbered 32 past the same bit of the word before.
* **TLVs.** Bit 28 makes the rest of the region a list of type-length-value
  items. An item's data is decoded where its type has a schema it does not run
  past, and kept raw otherwise; a vendor item is split into its header and raw
  data. radiotap.org lets a producer leave out the octets that end an item, which
  are then zeros, so an item short of its schema, or of the vendor header, is
  decoded as though they were there. Its decoded data records the cut as
  ``__short_read__``, as :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`
  does, so :meth:`Radiotap.make <pcapkit.protocols.link.radiotap.Radiotap.make>`
  writes the octets that were captured.
* **What is not decoded.** A radiotap-namespace bit no field is defined for --
  18, FreeBSD's XChannel, which radiotap.org lists as unofficial, and every one
  numbered 32 or more, the TLV-only types included -- or a field that runs
  past the region, ends the walk, since nothing after it can be located: an
  :class:`~pcapkit.protocols.data.link.radiotap.Unknown` entry keeps every
  octet from there on, and its ``reason`` says which of the two it was.

.. [*] <https://www.radiotap.org/>, its field pages and its
   ``radiotap-library``; the Linux kernel's
   ``include/net/ieee80211_radiotap.h`` and ``net/wireless/radiotap.c``; and
   Wireshark's ``packet-ieee80211-radiotap.c`` and
   ``packet-ieee80211-radiotap-iter.c``, all of which agree on the fixed start
   and the present-flags chaining described above, and on each field layout
   they give.

.. versionadded:: 1.6.0

"""
import collections
import collections.abc
from typing import TYPE_CHECKING, cast

from pcapkit.const.radiotap.field_type import FieldType as Enum_FieldType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.schema.padding import pad_length
from pcapkit.protocols.data.link.radiotap import EHT as Data_EHT
from pcapkit.protocols.data.link.radiotap import FHSS as Data_FHSS
from pcapkit.protocols.data.link.radiotap import HE as Data_HE
from pcapkit.protocols.data.link.radiotap import HEMU as Data_HEMU
from pcapkit.protocols.data.link.radiotap import LSIG as Data_LSIG
from pcapkit.protocols.data.link.radiotap import MCS as Data_MCS
from pcapkit.protocols.data.link.radiotap import S1G as Data_S1G
from pcapkit.protocols.data.link.radiotap import TLV as Data_TLV
from pcapkit.protocols.data.link.radiotap import TSFT as Data_TSFT
from pcapkit.protocols.data.link.radiotap import USIG as Data_USIG
from pcapkit.protocols.data.link.radiotap import VHT as Data_VHT
from pcapkit.protocols.data.link.radiotap import AMPDUStatus as Data_AMPDUStatus
from pcapkit.protocols.data.link.radiotap import Antenna as Data_Antenna
from pcapkit.protocols.data.link.radiotap import AntennaNoise as Data_AntennaNoise
from pcapkit.protocols.data.link.radiotap import AntennaSignal as Data_AntennaSignal
from pcapkit.protocols.data.link.radiotap import Channel as Data_Channel
from pcapkit.protocols.data.link.radiotap import DataRetries as Data_DataRetries
from pcapkit.protocols.data.link.radiotap import DBAntennaNoise as Data_DBAntennaNoise
from pcapkit.protocols.data.link.radiotap import DBAntennaSignal as Data_DBAntennaSignal
from pcapkit.protocols.data.link.radiotap import DBmTXPower as Data_DBmTXPower
from pcapkit.protocols.data.link.radiotap import DBTXAttenuation as Data_DBTXAttenuation
from pcapkit.protocols.data.link.radiotap import Flags as Data_Flags
from pcapkit.protocols.data.link.radiotap import HEData1 as Data_HEData1
from pcapkit.protocols.data.link.radiotap import HEData2 as Data_HEData2
from pcapkit.protocols.data.link.radiotap import HEMUFlags1 as Data_HEMUFlags1
from pcapkit.protocols.data.link.radiotap import HEMUFlags2 as Data_HEMUFlags2
from pcapkit.protocols.data.link.radiotap import HEMUOtherUser as Data_HEMUOtherUser
from pcapkit.protocols.data.link.radiotap import LockQuality as Data_LockQuality
from pcapkit.protocols.data.link.radiotap import MCSFlags as Data_MCSFlags
from pcapkit.protocols.data.link.radiotap import Radiotap as Data_Radiotap
from pcapkit.protocols.data.link.radiotap import RadiotapNamespace as Data_RadiotapNamespace
from pcapkit.protocols.data.link.radiotap import Rate as Data_Rate
from pcapkit.protocols.data.link.radiotap import RTSRetries as Data_RTSRetries
from pcapkit.protocols.data.link.radiotap import RXFlags as Data_RXFlags
from pcapkit.protocols.data.link.radiotap import Timestamp as Data_Timestamp
from pcapkit.protocols.data.link.radiotap import TLVFields as Data_TLVFields
from pcapkit.protocols.data.link.radiotap import TXAttenuation as Data_TXAttenuation
from pcapkit.protocols.data.link.radiotap import TXFlags as Data_TXFlags
from pcapkit.protocols.data.link.radiotap import Unknown as Data_Unknown
from pcapkit.protocols.data.link.radiotap import USIGCommon as Data_USIGCommon
from pcapkit.protocols.data.link.radiotap import VendorNamespace as Data_VendorNamespace
from pcapkit.protocols.data.link.radiotap import VendorTLV as Data_VendorTLV
from pcapkit.protocols.data.link.radiotap import ZeroLengthPSDU as Data_ZeroLengthPSDU
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.link.radiotap import EHT as Schema_EHT
from pcapkit.protocols.schema.link.radiotap import FHSS as Schema_FHSS
from pcapkit.protocols.schema.link.radiotap import HE as Schema_HE
from pcapkit.protocols.schema.link.radiotap import HEMU as Schema_HEMU
from pcapkit.protocols.schema.link.radiotap import LSIG as Schema_LSIG
from pcapkit.protocols.schema.link.radiotap import MCS as Schema_MCS
from pcapkit.protocols.schema.link.radiotap import S1G as Schema_S1G
from pcapkit.protocols.schema.link.radiotap import TLV as Schema_TLV
from pcapkit.protocols.schema.link.radiotap import TSFT as Schema_TSFT
from pcapkit.protocols.schema.link.radiotap import USIG as Schema_USIG
from pcapkit.protocols.schema.link.radiotap import VHT as Schema_VHT
from pcapkit.protocols.schema.link.radiotap import AMPDUStatus as Schema_AMPDUStatus
from pcapkit.protocols.schema.link.radiotap import Antenna as Schema_Antenna
from pcapkit.protocols.schema.link.radiotap import AntennaNoise as Schema_AntennaNoise
from pcapkit.protocols.schema.link.radiotap import AntennaSignal as Schema_AntennaSignal
from pcapkit.protocols.schema.link.radiotap import Channel as Schema_Channel
from pcapkit.protocols.schema.link.radiotap import DataRetries as Schema_DataRetries
from pcapkit.protocols.schema.link.radiotap import DBAntennaNoise as Schema_DBAntennaNoise
from pcapkit.protocols.schema.link.radiotap import DBAntennaSignal as Schema_DBAntennaSignal
from pcapkit.protocols.schema.link.radiotap import DBmTXPower as Schema_DBmTXPower
from pcapkit.protocols.schema.link.radiotap import DBTXAttenuation as Schema_DBTXAttenuation
from pcapkit.protocols.schema.link.radiotap import Flags as Schema_Flags
from pcapkit.protocols.schema.link.radiotap import HEMUOtherUser as Schema_HEMUOtherUser
from pcapkit.protocols.schema.link.radiotap import LockQuality as Schema_LockQuality
from pcapkit.protocols.schema.link.radiotap import Radiotap as Schema_Radiotap
from pcapkit.protocols.schema.link.radiotap import RadiotapField as Schema_Field
from pcapkit.protocols.schema.link.radiotap import Rate as Schema_Rate
from pcapkit.protocols.schema.link.radiotap import RTSRetries as Schema_RTSRetries
from pcapkit.protocols.schema.link.radiotap import RXFlags as Schema_RXFlags
from pcapkit.protocols.schema.link.radiotap import Timestamp as Schema_Timestamp
from pcapkit.protocols.schema.link.radiotap import TXAttenuation as Schema_TXAttenuation
from pcapkit.protocols.schema.link.radiotap import TXFlags as Schema_TXFlags
from pcapkit.protocols.schema.link.radiotap import Unknown as Schema_Unknown
from pcapkit.protocols.schema.link.radiotap import VendorNamespace as Schema_VendorNamespace
from pcapkit.protocols.schema.link.radiotap import VendorTLV as Schema_VendorTLV
from pcapkit.protocols.schema.link.radiotap import ZeroLengthPSDU as Schema_ZeroLengthPSDU
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import CaughtByCaller, FieldValueError, ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import (Any, Callable, ClassVar, DefaultDict, Iterator, Mapping, Optional, Sequence,
                        Tuple, Type, Union)

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.corekit.fields.numbers import BitmapField
    from pcapkit.protocols.data.link.radiotap import RadiotapField as Data_Field

    #: A field given to :meth:`Radiotap.make` -- a data model, or a ``(type, mapping)`` pair.
    FieldEntry = Union[Data_Field, Tuple[Union[Enum_FieldType, int], Mapping[str, Any]]]
    #: Parser of a field type registered as a callable -- the type and the
    #: parsed schema, to the data model.
    FieldParser = Callable[[Enum_FieldType, Schema_Field], Data_Field]
    #: Constructor of a field type registered as a callable -- the type and a
    #: data model or a mapping of its subfields, to the schema.
    FieldConstructor = Callable[[Enum_FieldType, Union[Data_Field, Mapping[str, Any]]], Schema_Field]

__all__ = ['Radiotap']

#: Bit 31 of an ``it_present`` word -- set, another present-flags word
#: follows; clear, the field-data region starts right after this word.
_IT_PRESENT_EXTENDED = 1 << 31

#: Octets of the fixed start every radiotap header has, before any extended
#: present-flags word or field data.
_FIXED_HEADER_LEN = 8

#: Octets of one present-flags word, extended or not.
_PRESENT_WORD_LEN = 4

#: Bits of one present-flags word.
_PRESENT_WORD_BITS = 8 * _PRESENT_WORD_LEN

#: The largest field type, the bound of a TLV's ``type``; a presence bit past
#: it ends the walk, see :meth:`Radiotap._walk_present`.
_FIELD_TYPE_MAX = (1 << 8 * Schema_TLV.__fields__['type'].length) - 1

#: Why an :class:`~pcapkit.protocols.data.link.radiotap.Unknown` entry ended
#: the walk, as its ``reason`` says.
_REASON_NO_LAYOUT = 'no layout is defined for the field type'
_REASON_PAST_REGION = 'the field runs past the field-data region'


class Radiotap(Link[Data_Radiotap, Schema_Radiotap],
               schema=Schema_Radiotap, data=Data_Radiotap):
    """This class implements the IEEE 802.11 radiotap header.

    The 802.11 MAC frame this header precedes is dispatched through the
    registry below, keyed by the link type of the frame:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.reg.linktype.LinkType.IEEE802_11`
         - :class:`pcapkit.protocols.link.ieee802_11.IEEE802_11`

    and each field of the field-data region through :attr:`__field__`, keyed
    by its :class:`~pcapkit.const.radiotap.field_type.FieldType`. See the
    module docstring's *Scope* and *Field Decoding* sections for what is, and
    is not, decoded.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, keyed by the link type
    #: of the frame the header precedes; :meth:`read` always looks up
    #: :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_LinkType.IEEE802_11: ModuleDescriptor('pcapkit.protocols.link.ieee802_11', 'IEEE802_11'),
        },
    )  # type: DefaultDict[int | Enum_LinkType, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: What :attr:`__proto__` is keyed by, declared as
    #: :attr:`Link.__proto_key__ <pcapkit.protocols.link.link.Link.__proto_key__>` is.
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_LinkType, False)

    #: Field type to method mapping, see :meth:`_read_radiotap_fields` and
    #: :meth:`_make_radiotap_fields`. A :obj:`str` value names the methods
    #: ``_read_field_${name}`` and ``_make_field_${name}``, any other value is a
    #: ``(parser, constructor)`` pair; either works on the type's schema in the
    #: :class:`~pcapkit.protocols.schema.link.radiotap.RadiotapField` registry. A
    #: type missing from either has no layout and is kept raw. Presence bits 28 to
    #: 30 and vendor namespace TLV items follow rules of their own, see the module
    #: docstring; a type from 32 on is reached as a TLV item only.
    __field__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_FieldType.TSFT: 'tsft',
            Enum_FieldType.Flags: 'flags',
            Enum_FieldType.Rate: 'rate',
            Enum_FieldType.Channel: 'channel',
            Enum_FieldType.FHSS: 'fhss',
            Enum_FieldType.Antenna_signal: 'antenna_signal',
            Enum_FieldType.Antenna_noise: 'antenna_noise',
            Enum_FieldType.Lock_quality: 'lock_quality',
            Enum_FieldType.TX_attenuation: 'tx_attenuation',
            Enum_FieldType.dB_TX_attenuation: 'db_tx_attenuation',
            Enum_FieldType.dBm_TX_power: 'dbm_tx_power',
            Enum_FieldType.Antenna: 'antenna',
            Enum_FieldType.dB_antenna_signal: 'db_antenna_signal',
            Enum_FieldType.dB_antenna_noise: 'db_antenna_noise',
            Enum_FieldType.RX_flags: 'rx_flags',
            Enum_FieldType.TX_flags: 'tx_flags',
            Enum_FieldType.RTS_retries: 'rts_retries',
            Enum_FieldType.data_retries: 'data_retries',
            Enum_FieldType.MCS: 'mcs',
            Enum_FieldType.A_MPDU_status: 'ampdu_status',
            Enum_FieldType.VHT: 'vht',
            Enum_FieldType.timestamp: 'timestamp',
            Enum_FieldType.HE: 'he',
            Enum_FieldType.HE_MU: 'he_mu',
            Enum_FieldType.HE_MU_other_user: 'he_mu_other_user',
            Enum_FieldType.FieldType_0_length_PSDU: 'zero_length_psdu',
            Enum_FieldType.L_SIG: 'lsig',
            Enum_FieldType.S1G: 's1g',
            Enum_FieldType.U_SIG: 'usig',
            Enum_FieldType.EHT: 'eht',
        },
    )  # type: DefaultDict[Enum_FieldType | int, str | tuple[FieldParser, FieldConstructor]]

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
        select, then by the 802.11 MAC frame at offset ``it_len``.

        The region is decoded into
        :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.decoded` as the
        module docstring's *Field Decoding* section describes: one entry per
        bit that selects radiotap-namespace data or switches namespace, keyed
        by its :class:`~pcapkit.const.radiotap.field_type.FieldType`. A bit in
        a vendor namespace has no entry of its own, since its data is in the
        :class:`~pcapkit.protocols.data.link.radiotap.VendorNamespace` entry,
        and nothing after the TLV fields or an
        :class:`~pcapkit.protocols.data.link.radiotap.Unknown` entry has one.
        Octets after the last field stay in
        :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.fields` alone.

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
        #: together -- see :meth:`_get_payload` for how the frame is
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
        #: int: Offset into the header schema's payload where the 802.11 MAC
        #: frame starts -- read by :meth:`_get_payload`.
        self._mac_offset = tail_offset  # pylint: disable=attribute-defined-outside-init

        radiotap = Data_Radiotap(
            it_version=it_version,
            it_pad=it_pad,
            it_len=it_len,
            present=tuple(present),
            fields=fields,
            decoded=self._read_radiotap_fields(present, fields),
        )
        header_len = _FIXED_HEADER_LEN + tail_offset
        return self._decode_next_layer(radiotap, Enum_LinkType.IEEE802_11, max(0, length - header_len))

    def make(self,
             it_version: 'int' = 0,
             it_pad: 'int' = 0,
             present: 'Sequence[int]' = (0,),
             fields: 'bytes | Mapping[Enum_FieldType | int, Data_Field | Mapping[str, Any]] | Sequence[FieldEntry]' = b'',  # pylint: disable=line-too-long
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
                for raw ``fields``, so a capture that read short of its own
                chain replays exactly: see the ``Note`` on
                :meth:`FRAD.make <pcapkit.protocols.link.frad.FRAD.make>`
                for the same tolerance).
            fields: The optional-field region ``present`` selects: the raw
                octets, written as they are, or its fields, which are
                encoded with zero padding. Fields are given as
                :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.decoded`
                holds them, or as a sequence of data models or
                ``(type, mapping)`` pairs, a type being a
                :class:`~pcapkit.const.radiotap.field_type.FieldType` or an
                :class:`int`. There is one per bit :meth:`read` gives an entry
                for, in the same order, and an
                :class:`~pcapkit.protocols.data.link.radiotap.Unknown` one, or
                one of a type no field is defined for, is written raw and
                ends the region.
            it_len: Total header length, header included; computed from
                ``present`` and ``fields`` when omitted.
            payload: Payload data (the 802.11 MAC frame).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``it_version`` or ``it_pad`` does not fit in
                8 bits; if ``present`` is empty or any of its words does not
                fit in 32 bits; if ``fields`` is neither :class:`bytes` nor
                fields; if the fields do not match the bits of ``present``,
                a word but the last of which ends the chain, or a value does
                not fit its subfield; if a TLV item's ``__short_read__`` names
                no field and an octet count, or cuts short a vendor header that
                data follows; or if ``it_len`` is given and does not fit in 16
                bits.

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

        if isinstance(fields, (bytes, bytearray)):
            fields_bytes = bytes(fields)
        elif not isinstance(fields, (collections.abc.Mapping, list, tuple)):
            raise ProtocolError(f'{self.alias}: invalid fields: {fields!r}, must be bytes or fields')
        else:
            fields_bytes = self._make_radiotap_fields(present, fields)

        if isinstance(payload, ProtocolBase):
            payload_bytes = bytes(payload)
        elif isinstance(payload, Schema):
            payload_bytes = payload.pack()
        else:
            payload_bytes = bytes(payload)

        chain_bytes = b''.join(word.to_bytes(_PRESENT_WORD_LEN, 'little') for word in present[1:])

        if it_len is None:
            it_len = _FIXED_HEADER_LEN + len(chain_bytes) + len(fields_bytes)
        elif (not isinstance(it_len, int) or isinstance(it_len, bool)
              or not 0 <= it_len <= 0xFFFF):
            raise ProtocolError(f'{self.alias}: invalid it_len: {it_len!r}')

        return Schema_Radiotap(
            it_version=it_version,
            it_pad=it_pad,
            it_len=it_len,
            it_present=present[0],
            payload=chain_bytes + fields_bytes + payload_bytes,
        )

    @classmethod
    def register(cls, code: 'Enum_LinkType',  # type: ignore[override]
                 protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
        r"""Register a new protocol class for the frame a radiotap header precedes.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: link type as in :class:`~pcapkit.const.reg.linktype.LinkType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Important:
            This overrides :meth:`Link.register
            <pcapkit.protocols.link.link.Link.register>` because
            :attr:`self.__proto__ <Radiotap.__proto__>` is keyed by link type
            rather than by EtherType. Any link type is accepted, but
            :meth:`read` consults
            :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`
            alone: that is the key a replacement 802.11 dissector takes, and
            an entry under any other key is stored and never reached.

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this link type is
                already registered and the incumbent differs from the
                replacement; see :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the guard,
                and for the shipped descriptor a restore puts back (:issue:`1504`).

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'link type {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def register_field(cls, code: 'Enum_FieldType', meth: 'str | tuple[FieldParser, FieldConstructor]') -> 'None':
        """Register a field parser.

        Args:
            code: Radiotap field type.
            meth: Method name, or a ``(parser, constructor)`` pair of
                callables, to parse and construct the field; see
                :attr:`__field__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op. Re-registering
                the entry ``code`` shipped with is accepted like any other,
                so an override can be undone (:issue:`1362`, :issue:`1363`).

        """
        incumbent = cls.__field__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'field type {code} already registered, overwriting', RegistryWarning)
        cls.__field__[code] = meth

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
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types.
            :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`
            names its own key for this class, ``ARPHRD_IEEE80211_RADIOTAP``
            (:ref:`registry-protocol-index`).

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.IEEE802_11_RADIOTAP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Radiotap') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        The field-data region is rebuilt from
        :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.fields`, the
        octets as captured, so padding, trailing octets and fields that were
        not decoded come back exactly; an edit to
        :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.decoded` takes
        a :meth:`make` call that passes it as ``fields``.

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

    def _read_radiotap_fields(self, present: 'Sequence[int]',
                              fields: 'bytes') -> 'OrderedMultiDict[Enum_FieldType, Data_Field]':
        """Decode the field-data region.

        Args:
            present: Every present-flags word read.
            fields: The field-data region.

        Returns:
            The decoded fields, as :meth:`read` describes them.

        """
        decoded = OrderedMultiDict()  # type: OrderedMultiDict[Enum_FieldType, Data_Field]
        start = _FIXED_HEADER_LEN + _PRESENT_WORD_LEN * (len(present) - 1)
        pos = 0
        for index in self._walk_present(present):
            field_type = Enum_FieldType.get(index)
            if index == Enum_FieldType.Radiotap_Namespace:
                decoded.add(field_type, Data_RadiotapNamespace(type=field_type))
                continue

            found = None  # type: Optional[tuple[Data_Field, int]]
            if index == Enum_FieldType.Vendor_Namespace:
                found = self._read_vendor_namespace(field_type, fields, pos, start)
            elif index == Enum_FieldType.TLV_fields_in_radiotap:
                found = self._read_tlv_fields(field_type, fields, pos, start)
            else:
                found = self._read_present_field(field_type, fields, pos, start)

            if found is None:
                found = self._read_field_unknown(field_type, Schema_Unknown(data=fields[pos:]),
                                                 reason=_REASON_PAST_REGION), len(fields)
            entry, pos = found
            decoded.add(field_type, entry)
            if isinstance(entry, Data_Unknown) or index == Enum_FieldType.TLV_fields_in_radiotap:
                break
        return decoded

    def _make_radiotap_fields(self, present: 'Sequence[int]',
                              fields: 'Mapping[Enum_FieldType | int, Data_Field | Mapping[str, Any]] | Sequence[FieldEntry]') -> 'bytes':  # pylint: disable=line-too-long
        """Encode the field-data region, the inverse of :meth:`_read_radiotap_fields`.

        Args:
            present: Every present-flags word.
            fields: The fields, as :meth:`make` takes them.

        Returns:
            The field-data region.

        Raises:
            ProtocolError: If the fields do not match the bits of ``present``,
                a word but the last of which ends the chain, or a value does
                not fit its subfield.

        """
        for number, word in enumerate(present[:-1]):
            if not word & _IT_PRESENT_EXTENDED:
                raise ProtocolError(f'{self.alias}: invalid present: word {number} ends the chain, '
                                    'but more follow')

        entries = []  # type: list[tuple[Enum_FieldType, Mapping[str, Any]]]
        if isinstance(fields, collections.abc.Mapping):
            items = fields.items(multi=True) if isinstance(fields, OrderedMultiDict) else fields.items()
            entries.extend((Enum_FieldType.get(key), value) for key, value in items)
        else:
            for item in fields:
                if isinstance(item, tuple):
                    entries.append((Enum_FieldType.get(item[0]), item[1]))
                else:
                    entries.append((Enum_FieldType.get(item['type']), item))

        out = bytearray()
        start = _FIXED_HEADER_LEN + _PRESENT_WORD_LEN * (len(present) - 1)
        given = iter(entries)
        for index in self._walk_present(present):
            expected = Enum_FieldType.get(index)
            pair = next(given, None)
            if pair is None:
                raise ProtocolError(f'{self.alias}: invalid fields: none given for {expected!r}')
            field_type, entry = pair
            if field_type != expected:
                raise ProtocolError(f'{self.alias}: invalid fields: {field_type!r} given where '
                                    f'present selects {expected!r}')

            layout = None if index >= Enum_FieldType.TLV_fields_in_radiotap else self._lookup_field(expected)
            if index in (Enum_FieldType.TLV_fields_in_radiotap, Enum_FieldType.Radiotap_Namespace,
                         Enum_FieldType.Vendor_Namespace):
                decodable = True
            else:
                decodable = layout is not None and not self._field_size(layout[2])[1]
            if isinstance(entry, Data_Unknown) or not decodable:
                out += self._make_field_unknown(expected, entry).pack()
                break
            if index == Enum_FieldType.Radiotap_Namespace:
                continue

            pos = start + len(out)
            if index == Enum_FieldType.Vendor_Namespace:
                out += self._make_vendor_namespace(entry, pos)
            elif index == Enum_FieldType.TLV_fields_in_radiotap:
                out += self._make_tlv_fields(entry, pos)
                break
            else:
                _, constructor, schema = layout  # type: ignore[misc]
                out += bytes(pad_length(pos, schema.__align__))
                out += constructor(expected, entry).pack()

        left = sum(1 for _ in given)
        if left:
            raise ProtocolError(f'{self.alias}: invalid fields: {left} given past what present selects')
        return bytes(out)

    def _read_field_unknown(self, field_type: 'Enum_FieldType', schema: 'Schema_Unknown', *,
                            reason: 'str' = _REASON_NO_LAYOUT) -> 'Data_Unknown':
        """Read the octets of a field type with no layout, or of a field that
        runs past the field-data region.

        Args:
            field_type: type of the field
            schema: parsed field schema, every octet to the end of the region
            reason: why the field is not decoded

        Returns:
            Parsed field data.

        """
        return Data_Unknown(type=field_type, data=schema.data, reason=reason)

    def _read_field_tsft(self, field_type: 'Enum_FieldType', schema: 'Schema_TSFT') -> 'Data_TSFT':
        """Read a TSFT field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_TSFT(type=field_type, mactime=schema.mactime)

    def _read_field_flags(self, field_type: 'Enum_FieldType', schema: 'Schema_Flags') -> 'Data_Flags':
        """Read a Flags field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_Flags(type=field_type, flags=schema.flags)

    def _read_field_rate(self, field_type: 'Enum_FieldType', schema: 'Schema_Rate') -> 'Data_Rate':
        """Read a Rate field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_Rate(type=field_type, rate=schema.rate)

    def _read_field_channel(self, field_type: 'Enum_FieldType', schema: 'Schema_Channel') -> 'Data_Channel':
        """Read a Channel field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_Channel(type=field_type, frequency=schema.frequency, flags=schema.flags)

    def _read_field_fhss(self, field_type: 'Enum_FieldType', schema: 'Schema_FHSS') -> 'Data_FHSS':
        """Read an FHSS field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_FHSS(type=field_type, hop_set=schema.hop_set, hop_pattern=schema.hop_pattern)

    def _read_field_antenna_signal(self, field_type: 'Enum_FieldType',
                                   schema: 'Schema_AntennaSignal') -> 'Data_AntennaSignal':
        """Read an Antenna signal field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_AntennaSignal(type=field_type, signal=schema.signal)

    def _read_field_antenna_noise(self, field_type: 'Enum_FieldType',
                                  schema: 'Schema_AntennaNoise') -> 'Data_AntennaNoise':
        """Read an Antenna noise field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_AntennaNoise(type=field_type, noise=schema.noise)

    def _read_field_lock_quality(self, field_type: 'Enum_FieldType',
                                 schema: 'Schema_LockQuality') -> 'Data_LockQuality':
        """Read a Lock quality field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_LockQuality(type=field_type, quality=schema.quality)

    def _read_field_tx_attenuation(self, field_type: 'Enum_FieldType',
                                   schema: 'Schema_TXAttenuation') -> 'Data_TXAttenuation':
        """Read a TX attenuation field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_TXAttenuation(type=field_type, attenuation=schema.attenuation)

    def _read_field_db_tx_attenuation(self, field_type: 'Enum_FieldType',
                                      schema: 'Schema_DBTXAttenuation') -> 'Data_DBTXAttenuation':
        """Read a dB TX attenuation field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_DBTXAttenuation(type=field_type, attenuation=schema.attenuation)

    def _read_field_dbm_tx_power(self, field_type: 'Enum_FieldType',
                                 schema: 'Schema_DBmTXPower') -> 'Data_DBmTXPower':
        """Read a dBm TX power field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_DBmTXPower(type=field_type, power=schema.power)

    def _read_field_antenna(self, field_type: 'Enum_FieldType', schema: 'Schema_Antenna') -> 'Data_Antenna':
        """Read an Antenna field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_Antenna(type=field_type, antenna=schema.antenna)

    def _read_field_db_antenna_signal(self, field_type: 'Enum_FieldType',
                                      schema: 'Schema_DBAntennaSignal') -> 'Data_DBAntennaSignal':
        """Read a dB antenna signal field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_DBAntennaSignal(type=field_type, signal=schema.signal)

    def _read_field_db_antenna_noise(self, field_type: 'Enum_FieldType',
                                     schema: 'Schema_DBAntennaNoise') -> 'Data_DBAntennaNoise':
        """Read a dB antenna noise field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_DBAntennaNoise(type=field_type, noise=schema.noise)

    def _read_field_rx_flags(self, field_type: 'Enum_FieldType', schema: 'Schema_RXFlags') -> 'Data_RXFlags':
        """Read an RX flags field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_RXFlags(type=field_type, flags=schema.flags)

    def _read_field_tx_flags(self, field_type: 'Enum_FieldType', schema: 'Schema_TXFlags') -> 'Data_TXFlags':
        """Read a TX flags field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_TXFlags(type=field_type, flags=schema.flags)

    def _read_field_rts_retries(self, field_type: 'Enum_FieldType',
                                schema: 'Schema_RTSRetries') -> 'Data_RTSRetries':
        """Read an RTS retries field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_RTSRetries(type=field_type, retries=schema.retries)

    def _read_field_data_retries(self, field_type: 'Enum_FieldType',
                                 schema: 'Schema_DataRetries') -> 'Data_DataRetries':
        """Read a data retries field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_DataRetries(type=field_type, retries=schema.retries)

    def _read_field_mcs(self, field_type: 'Enum_FieldType', schema: 'Schema_MCS') -> 'Data_MCS':
        """Read an MCS field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_MCS(type=field_type, known=schema.known, flags=Data_MCSFlags(**schema.flags),
                        mcs=schema.mcs)

    def _read_field_ampdu_status(self, field_type: 'Enum_FieldType',
                                 schema: 'Schema_AMPDUStatus') -> 'Data_AMPDUStatus':
        """Read an A-MPDU status field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_AMPDUStatus(type=field_type, reference=schema.reference, flags=schema.flags,
                                delimiter_crc=schema.delimiter_crc, reserved=schema.reserved)

    def _read_field_vht(self, field_type: 'Enum_FieldType', schema: 'Schema_VHT') -> 'Data_VHT':
        """Read a VHT field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_VHT(type=field_type, known=schema.known, flags=schema.flags, bandwidth=schema.bandwidth,
                        mcs_nss=cast('tuple[int, int, int, int]', tuple(schema.mcs_nss)),
                        coding=schema.coding, group_id=schema.group_id,
                        partial_aid=schema.partial_aid)

    def _read_field_timestamp(self, field_type: 'Enum_FieldType', schema: 'Schema_Timestamp') -> 'Data_Timestamp':
        """Read a timestamp field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_Timestamp(type=field_type, timestamp=schema.timestamp, accuracy=schema.accuracy,
                              unit_position=schema.unit_position, flags=schema.flags)

    def _read_field_he(self, field_type: 'Enum_FieldType', schema: 'Schema_HE') -> 'Data_HE':
        """Read an HE field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_HE(type=field_type, data1=Data_HEData1(**schema.data1), data2=Data_HEData2(**schema.data2),
                       data3=schema.data3,
                       data4=schema.data4, data5=schema.data5, data6=schema.data6)

    def _read_field_he_mu(self, field_type: 'Enum_FieldType', schema: 'Schema_HEMU') -> 'Data_HEMU':
        """Read an HE-MU field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_HEMU(type=field_type, flags1=Data_HEMUFlags1(**schema.flags1),
                         flags2=Data_HEMUFlags2(**schema.flags2),
                         ru_channel1=cast('tuple[int, int, int, int]', tuple(schema.ru_channel1)),
                         ru_channel2=cast('tuple[int, int, int, int]', tuple(schema.ru_channel2)))

    def _read_field_he_mu_other_user(self, field_type: 'Enum_FieldType',
                                     schema: 'Schema_HEMUOtherUser') -> 'Data_HEMUOtherUser':
        """Read an HE-MU-other-user field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_HEMUOtherUser(type=field_type, per_user_1=schema.per_user_1, per_user_2=schema.per_user_2,
                                  per_user_position=schema.per_user_position,
                                  per_user_known=schema.per_user_known)

    def _read_field_zero_length_psdu(self, field_type: 'Enum_FieldType',
                                     schema: 'Schema_ZeroLengthPSDU') -> 'Data_ZeroLengthPSDU':
        """Read a 0-length-PSDU field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_ZeroLengthPSDU(type=field_type, psdu_type=schema.psdu_type)

    def _read_field_lsig(self, field_type: 'Enum_FieldType', schema: 'Schema_LSIG') -> 'Data_LSIG':
        """Read an L-SIG field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_LSIG(type=field_type, data1=schema.data1, data2=schema.data2)

    def _read_field_s1g(self, field_type: 'Enum_FieldType', schema: 'Schema_S1G') -> 'Data_S1G':
        """Read an S1G field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_S1G(type=field_type, known=schema.known, data1=schema.data1, data2=schema.data2)

    def _read_field_usig(self, field_type: 'Enum_FieldType', schema: 'Schema_USIG') -> 'Data_USIG':
        """Read a U-SIG field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_USIG(type=field_type, common=Data_USIGCommon(**schema.common), value=schema.value,
                         mask=schema.mask)

    def _read_field_eht(self, field_type: 'Enum_FieldType', schema: 'Schema_EHT') -> 'Data_EHT':
        """Read an EHT field.

        Args:
            field_type: type of the field
            schema: parsed field schema

        Returns:
            Parsed field data.

        """
        return Data_EHT(type=field_type, known=schema.known, data=tuple(schema.data),
                        user_info=tuple(schema.user_info))

    def _make_field_unknown(self, field_type: 'Enum_FieldType',
                            entry: 'Data_Field | Mapping[str, Any]') -> 'Schema_Unknown':
        """Make the octets of a field that is written raw: an unknown one, or
        one of a type with no layout.

        Args:
            field_type: type of the field
            entry: field data, whose ``data`` is the octets

        Returns:
            Constructed field schema.

        Raises:
            ProtocolError: If ``data`` is not :class:`bytes`.

        """
        data = entry.get('data')
        if not isinstance(data, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid fields: {field_type!r} is written raw, '
                                f'so its data must be bytes, not {data!r}')
        return Schema_Unknown(data=bytes(data))

    def _make_field_tsft(self, field_type: 'Enum_FieldType',
                         entry: 'Data_TSFT | Mapping[str, Any]') -> 'Schema_TSFT':
        """Make a TSFT field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_TSFT(mactime=self._make_subfield(field_type, Schema_TSFT, entry, 'mactime'))

    def _make_field_flags(self, field_type: 'Enum_FieldType',
                          entry: 'Data_Flags | Mapping[str, Any]') -> 'Schema_Flags':
        """Make a Flags field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_Flags(flags=self._make_subfield(field_type, Schema_Flags, entry, 'flags'))

    def _make_field_rate(self, field_type: 'Enum_FieldType',
                         entry: 'Data_Rate | Mapping[str, Any]') -> 'Schema_Rate':
        """Make a Rate field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_Rate(rate=self._make_subfield(field_type, Schema_Rate, entry, 'rate'))

    def _make_field_channel(self, field_type: 'Enum_FieldType',
                            entry: 'Data_Channel | Mapping[str, Any]') -> 'Schema_Channel':
        """Make a Channel field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_Channel(
            frequency=self._make_subfield(field_type, Schema_Channel, entry, 'frequency'),
            flags=self._make_subfield(field_type, Schema_Channel, entry, 'flags'),
        )

    def _make_field_fhss(self, field_type: 'Enum_FieldType',
                         entry: 'Data_FHSS | Mapping[str, Any]') -> 'Schema_FHSS':
        """Make an FHSS field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_FHSS(
            hop_set=self._make_subfield(field_type, Schema_FHSS, entry, 'hop_set'),
            hop_pattern=self._make_subfield(field_type, Schema_FHSS, entry, 'hop_pattern'),
        )

    def _make_field_antenna_signal(self, field_type: 'Enum_FieldType',
                                   entry: 'Data_AntennaSignal | Mapping[str, Any]') -> 'Schema_AntennaSignal':
        """Make an Antenna signal field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_AntennaSignal(signal=self._make_subfield(field_type, Schema_AntennaSignal, entry, 'signal'))

    def _make_field_antenna_noise(self, field_type: 'Enum_FieldType',
                                  entry: 'Data_AntennaNoise | Mapping[str, Any]') -> 'Schema_AntennaNoise':
        """Make an Antenna noise field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_AntennaNoise(noise=self._make_subfield(field_type, Schema_AntennaNoise, entry, 'noise'))

    def _make_field_lock_quality(self, field_type: 'Enum_FieldType',
                                 entry: 'Data_LockQuality | Mapping[str, Any]') -> 'Schema_LockQuality':
        """Make a Lock quality field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_LockQuality(quality=self._make_subfield(field_type, Schema_LockQuality, entry, 'quality'))

    def _make_field_tx_attenuation(self, field_type: 'Enum_FieldType',
                                   entry: 'Data_TXAttenuation | Mapping[str, Any]') -> 'Schema_TXAttenuation':
        """Make a TX attenuation field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_TXAttenuation(
            attenuation=self._make_subfield(field_type, Schema_TXAttenuation, entry, 'attenuation'),
        )

    def _make_field_db_tx_attenuation(self, field_type: 'Enum_FieldType',
                                      entry: 'Data_DBTXAttenuation | Mapping[str, Any]') -> 'Schema_DBTXAttenuation':
        """Make a dB TX attenuation field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_DBTXAttenuation(
            attenuation=self._make_subfield(field_type, Schema_DBTXAttenuation, entry, 'attenuation'),
        )

    def _make_field_dbm_tx_power(self, field_type: 'Enum_FieldType',
                                 entry: 'Data_DBmTXPower | Mapping[str, Any]') -> 'Schema_DBmTXPower':
        """Make a dBm TX power field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_DBmTXPower(power=self._make_subfield(field_type, Schema_DBmTXPower, entry, 'power'))

    def _make_field_antenna(self, field_type: 'Enum_FieldType',
                            entry: 'Data_Antenna | Mapping[str, Any]') -> 'Schema_Antenna':
        """Make an Antenna field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_Antenna(antenna=self._make_subfield(field_type, Schema_Antenna, entry, 'antenna'))

    def _make_field_db_antenna_signal(self, field_type: 'Enum_FieldType',
                                      entry: 'Data_DBAntennaSignal | Mapping[str, Any]') -> 'Schema_DBAntennaSignal':
        """Make a dB antenna signal field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_DBAntennaSignal(signal=self._make_subfield(field_type, Schema_DBAntennaSignal, entry, 'signal'))

    def _make_field_db_antenna_noise(self, field_type: 'Enum_FieldType',
                                     entry: 'Data_DBAntennaNoise | Mapping[str, Any]') -> 'Schema_DBAntennaNoise':
        """Make a dB antenna noise field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_DBAntennaNoise(noise=self._make_subfield(field_type, Schema_DBAntennaNoise, entry, 'noise'))

    def _make_field_rx_flags(self, field_type: 'Enum_FieldType',
                             entry: 'Data_RXFlags | Mapping[str, Any]') -> 'Schema_RXFlags':
        """Make an RX flags field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_RXFlags(flags=self._make_subfield(field_type, Schema_RXFlags, entry, 'flags'))

    def _make_field_tx_flags(self, field_type: 'Enum_FieldType',
                             entry: 'Data_TXFlags | Mapping[str, Any]') -> 'Schema_TXFlags':
        """Make a TX flags field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_TXFlags(flags=self._make_subfield(field_type, Schema_TXFlags, entry, 'flags'))

    def _make_field_rts_retries(self, field_type: 'Enum_FieldType',
                                entry: 'Data_RTSRetries | Mapping[str, Any]') -> 'Schema_RTSRetries':
        """Make an RTS retries field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_RTSRetries(retries=self._make_subfield(field_type, Schema_RTSRetries, entry, 'retries'))

    def _make_field_data_retries(self, field_type: 'Enum_FieldType',
                                 entry: 'Data_DataRetries | Mapping[str, Any]') -> 'Schema_DataRetries':
        """Make a data retries field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_DataRetries(retries=self._make_subfield(field_type, Schema_DataRetries, entry, 'retries'))

    def _make_field_mcs(self, field_type: 'Enum_FieldType', entry: 'Data_MCS | Mapping[str, Any]') -> 'Schema_MCS':
        """Make an MCS field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_MCS(
            known=self._make_subfield(field_type, Schema_MCS, entry, 'known'),
            flags=self._make_subfield_bitmap(field_type, Schema_MCS, entry, 'flags'),
            mcs=self._make_subfield(field_type, Schema_MCS, entry, 'mcs'),
        )

    def _make_field_ampdu_status(self, field_type: 'Enum_FieldType',
                                 entry: 'Data_AMPDUStatus | Mapping[str, Any]') -> 'Schema_AMPDUStatus':
        """Make an A-MPDU status field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_AMPDUStatus(
            reference=self._make_subfield(field_type, Schema_AMPDUStatus, entry, 'reference'),
            flags=self._make_subfield(field_type, Schema_AMPDUStatus, entry, 'flags'),
            delimiter_crc=self._make_subfield(field_type, Schema_AMPDUStatus, entry, 'delimiter_crc'),
            reserved=self._make_subfield(field_type, Schema_AMPDUStatus, entry, 'reserved'),
        )

    def _make_field_vht(self, field_type: 'Enum_FieldType', entry: 'Data_VHT | Mapping[str, Any]') -> 'Schema_VHT':
        """Make a VHT field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_VHT(
            known=self._make_subfield(field_type, Schema_VHT, entry, 'known'),
            flags=self._make_subfield(field_type, Schema_VHT, entry, 'flags'),
            bandwidth=self._make_subfield(field_type, Schema_VHT, entry, 'bandwidth'),
            mcs_nss=self._make_subfield_list(field_type, Schema_VHT, entry, 'mcs_nss'),
            coding=self._make_subfield(field_type, Schema_VHT, entry, 'coding'),
            group_id=self._make_subfield(field_type, Schema_VHT, entry, 'group_id'),
            partial_aid=self._make_subfield(field_type, Schema_VHT, entry, 'partial_aid'),
        )

    def _make_field_timestamp(self, field_type: 'Enum_FieldType',
                              entry: 'Data_Timestamp | Mapping[str, Any]') -> 'Schema_Timestamp':
        """Make a timestamp field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_Timestamp(
            timestamp=self._make_subfield(field_type, Schema_Timestamp, entry, 'timestamp'),
            accuracy=self._make_subfield(field_type, Schema_Timestamp, entry, 'accuracy'),
            unit_position=self._make_subfield(field_type, Schema_Timestamp, entry, 'unit_position'),
            flags=self._make_subfield(field_type, Schema_Timestamp, entry, 'flags'),
        )

    def _make_field_he(self, field_type: 'Enum_FieldType', entry: 'Data_HE | Mapping[str, Any]') -> 'Schema_HE':
        """Make an HE field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_HE(
            data1=self._make_subfield_bitmap(field_type, Schema_HE, entry, 'data1'),
            data2=self._make_subfield_bitmap(field_type, Schema_HE, entry, 'data2'),
            data3=self._make_subfield(field_type, Schema_HE, entry, 'data3'),
            data4=self._make_subfield(field_type, Schema_HE, entry, 'data4'),
            data5=self._make_subfield(field_type, Schema_HE, entry, 'data5'),
            data6=self._make_subfield(field_type, Schema_HE, entry, 'data6'),
        )

    def _make_field_he_mu(self, field_type: 'Enum_FieldType',
                          entry: 'Data_HEMU | Mapping[str, Any]') -> 'Schema_HEMU':
        """Make an HE-MU field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_HEMU(
            flags1=self._make_subfield_bitmap(field_type, Schema_HEMU, entry, 'flags1'),
            flags2=self._make_subfield_bitmap(field_type, Schema_HEMU, entry, 'flags2'),
            ru_channel1=self._make_subfield_list(field_type, Schema_HEMU, entry, 'ru_channel1'),
            ru_channel2=self._make_subfield_list(field_type, Schema_HEMU, entry, 'ru_channel2'),
        )

    def _make_field_he_mu_other_user(self, field_type: 'Enum_FieldType',
                                     entry: 'Data_HEMUOtherUser | Mapping[str, Any]') -> 'Schema_HEMUOtherUser':
        """Make an HE-MU-other-user field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_HEMUOtherUser(
            per_user_1=self._make_subfield(field_type, Schema_HEMUOtherUser, entry, 'per_user_1'),
            per_user_2=self._make_subfield(field_type, Schema_HEMUOtherUser, entry, 'per_user_2'),
            per_user_position=self._make_subfield(field_type, Schema_HEMUOtherUser, entry, 'per_user_position'),
            per_user_known=self._make_subfield(field_type, Schema_HEMUOtherUser, entry, 'per_user_known'),
        )

    def _make_field_zero_length_psdu(self, field_type: 'Enum_FieldType',
                                     entry: 'Data_ZeroLengthPSDU | Mapping[str, Any]') -> 'Schema_ZeroLengthPSDU':
        """Make a 0-length-PSDU field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_ZeroLengthPSDU(
            psdu_type=self._make_subfield(field_type, Schema_ZeroLengthPSDU, entry, 'psdu_type'),
        )

    def _make_field_lsig(self, field_type: 'Enum_FieldType', entry: 'Data_LSIG | Mapping[str, Any]') -> 'Schema_LSIG':
        """Make an L-SIG field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_LSIG(
            data1=self._make_subfield(field_type, Schema_LSIG, entry, 'data1'),
            data2=self._make_subfield(field_type, Schema_LSIG, entry, 'data2'),
        )

    def _make_field_s1g(self, field_type: 'Enum_FieldType', entry: 'Data_S1G | Mapping[str, Any]') -> 'Schema_S1G':
        """Make an S1G field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_S1G(
            known=self._make_subfield(field_type, Schema_S1G, entry, 'known'),
            data1=self._make_subfield(field_type, Schema_S1G, entry, 'data1'),
            data2=self._make_subfield(field_type, Schema_S1G, entry, 'data2'),
        )

    def _make_field_usig(self, field_type: 'Enum_FieldType', entry: 'Data_USIG | Mapping[str, Any]') -> 'Schema_USIG':
        """Make a U-SIG field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_USIG(
            common=self._make_subfield_bitmap(field_type, Schema_USIG, entry, 'common'),
            value=self._make_subfield(field_type, Schema_USIG, entry, 'value'),
            mask=self._make_subfield(field_type, Schema_USIG, entry, 'mask'),
        )

    def _make_field_eht(self, field_type: 'Enum_FieldType', entry: 'Data_EHT | Mapping[str, Any]') -> 'Schema_EHT':
        """Make an EHT field.

        Args:
            field_type: type of the field
            entry: field data, a data model or a mapping of its subfields

        Returns:
            Constructed field schema.

        """
        return Schema_EHT(
            known=self._make_subfield(field_type, Schema_EHT, entry, 'known'),
            data=self._make_subfield_list(field_type, Schema_EHT, entry, 'data'),
            user_info=self._make_subfield_list(field_type, Schema_EHT, entry, 'user_info'),
        )

    def _get_payload(self) -> 'bytes':
        """Get the 802.11 MAC frame this header precedes.

        The header schema's payload starts right after the fixed 8-octet
        start, so it also holds the present-flags chain and the field-data
        region it selects; those belong to this header, and the frame starts
        ``self._mac_offset`` octets in, as :meth:`read` records it. Both
        :meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`
        and the :class:`~pcapkit.protocols.misc.raw.Raw` that
        :func:`~pcapkit.corekit.decorators.beholder` falls back to on a
        refused frame read from here.

        Returns:
            The 802.11 MAC frame, as :obj:`bytes`.

        """
        return self.__header__.get_payload()[self._mac_offset:]

    @staticmethod
    def _walk_present(present: 'Sequence[int]') -> 'Iterator[int]':
        """Walk the present-flags words, in wire order.

        Bit 31 of each word is skipped, since it only chains the next word. A
        radiotap-namespace bit whose index passes the largest field type ends
        the walk, which takes a chain of more than 2048 words.

        Args:
            present: Every present-flags word.

        Yields:
            ``29`` or ``30`` for a namespace field, in any word; and, for a
            bit of a radiotap-namespace word, its index in the namespace, which
            is its field type. A bit of a vendor-namespace word yields nothing.

        """
        base = 0
        vendor = False
        for word in present:
            switch = None
            for bit in range(_PRESENT_WORD_BITS - 1):
                if not word >> bit & 1:
                    continue
                if bit in (Enum_FieldType.Radiotap_Namespace, Enum_FieldType.Vendor_Namespace):
                    switch = bit
                    yield bit
                elif not vendor:
                    if base + bit > _FIELD_TYPE_MAX:
                        return
                    yield base + bit
            if switch is None:
                base += _PRESENT_WORD_BITS
            else:
                base = 0
                vendor = switch == Enum_FieldType.Vendor_Namespace

    def _lookup_field(self, field_type: 'Enum_FieldType') -> 'Optional[tuple[FieldParser, FieldConstructor, Type[Schema_Field]]]':  # pylint: disable=line-too-long
        """Look up the parser, constructor and schema of a field type.

        Args:
            field_type: type of the field

        Returns:
            What :attr:`__field__` and the
            :class:`~pcapkit.protocols.schema.link.radiotap.RadiotapField`
            registry hold for ``field_type``; :obj:`None` if either has no
            entry for it, or if :attr:`__field__` names a method the class does
            not have, since the type then has no layout.

        """
        name = self._lookup_registry(self.__field__, field_type)
        schema = Schema_Field.registry[field_type]  # pylint: disable=unsubscriptable-object
        if name == 'unknown' or schema is Schema_Unknown:
            return None
        if not isinstance(name, str):
            return name[0], name[1], schema
        parser = getattr(self, f'_read_field_{name}', None)
        constructor = getattr(self, f'_make_field_{name}', None)
        if parser is None or constructor is None:
            return None
        return parser, constructor, schema

    @staticmethod
    def _field_size(schema: 'Type[Schema]') -> 'tuple[int, bool]':
        """Size the fields of ``schema``, a radiotap field or a part of one.

        Args:
            schema: the schema

        Returns:
            The octets of its fields up to the first whose length is not
            fixed, a list taking the rest of what holds the field, and whether
            there is one.

        """
        size = 0
        for field in schema.__fields__.values():
            if field.length < 0:
                return size, True
            size += field.length
        return size, False

    def _read_present_field(self, field_type: 'Enum_FieldType', fields: 'bytes', pos: 'int',
                            start: 'int') -> 'Optional[tuple[Data_Field, int]]':
        """Decode a field of the radiotap namespace a presence bit selects.

        Args:
            field_type: type of the field
            fields: The field-data region.
            pos: Offset in ``fields`` where the field may start, before
                alignment.
            start: Offset of ``fields`` from the start of the header.

        Returns:
            The field, and the offset in ``fields`` just past it; an
            :class:`~pcapkit.protocols.data.link.radiotap.Unknown` entry of the
            rest of ``fields`` for a type with no layout, or one that only a
            TLV carries; :obj:`None` if the field runs past ``fields``.

        """
        layout = None if field_type >= Enum_FieldType.TLV_fields_in_radiotap else self._lookup_field(field_type)
        if layout is None or self._field_size(layout[2])[1]:
            return self._read_field_unknown(field_type, Schema_Unknown(data=fields[pos:])), len(fields)

        parser, _, schema = layout
        size, _ = self._field_size(schema)
        offset = pos + pad_length(start + pos, schema.__align__)
        data = fields[offset:offset + size]
        if len(data) != size:
            return None
        return parser(field_type, schema.unpack(data, size, None)), offset + size  # type: ignore[call-arg,misc]

    def _make_subfield(self, field_type: 'Enum_FieldType', schema: 'Type[Schema]',
                       entry: 'Mapping[str, Any]', name: 'str') -> 'int':
        """Check an integer subfield of ``entry`` against the field of ``schema`` that holds it.

        Args:
            field_type: type of the field, for the error message
            schema: field schema
            entry: a data model or a mapping holding the subfield
            name: name of the subfield

        Returns:
            The subfield's value, as a plain :class:`int`.

        Raises:
            ProtocolError: If the subfield is missing, or does not fit in its
                field, signed as the field is.

        """
        what = f'{field_type.name}.{name}'
        if name not in entry:
            raise ProtocolError(f'{self.alias}: invalid fields: {what} missing')
        field = schema.__fields__[name]
        if getattr(field, '__signed__', None):
            return self._make_sint(entry[name], bits=8 * field.length, name=what)
        return self._make_uint(entry[name], bits=8 * field.length, name=what)

    def _make_subfield_list(self, field_type: 'Enum_FieldType', schema: 'Type[Schema]',
                            entry: 'Mapping[str, Any]', name: 'str') -> 'tuple[int, ...]':
        """Check a list subfield of ``entry`` against the field of ``schema`` that holds it.

        Args:
            field_type: type of the field, for the error message
            schema: field schema
            entry: a data model or a mapping holding the subfield
            name: name of the subfield

        Returns:
            The subfield's values.

        Raises:
            ProtocolError: If the subfield is missing, is not a list or tuple
                of as many values as its field holds, or a value does not fit.

        """
        what = f'{field_type.name}.{name}'
        if name not in entry:
            raise ProtocolError(f'{self.alias}: invalid fields: {what} missing')
        value = entry[name]
        field = schema.__fields__[name]
        # NOTE: ``ListField`` keeps its item field private; its width is what
        # a value has to fit in, and the list's length is the count of values.
        item = field._item_type if isinstance(field, ListField) else None  # pylint: disable=protected-access
        if not isinstance(value, (list, tuple)) or item is None:
            raise ProtocolError(f'{self.alias}: invalid {what}: {value!r}, must be a list of values')
        if field.length >= 0 and len(value) * item.length != field.length:
            raise ProtocolError(f'{self.alias}: invalid {what}: {value!r}, '
                                f'must have {field.length // item.length} values')
        return tuple(self._make_uint(number, bits=8 * item.length, name=what) for number in value)

    def _make_subfield_bitmap(self, field_type: 'Enum_FieldType', schema: 'Type[Schema]',
                              entry: 'Mapping[str, Any]', name: 'str') -> 'Any':
        """Check a bitmap subfield of ``entry`` against the field of ``schema`` that holds it.

        Args:
            field_type: type of the field, for the error message
            schema: field schema
            entry: a data model or a mapping holding the subfield
            name: name of the subfield

        Returns:
            The value of each of the bitmap's subfields, and of its known bits,
            as the schema's typed dictionary for the bitmap.

        Raises:
            ProtocolError: If the subfield is missing or is not a mapping, one of
                its own is missing or does not fit in its bits, or its known bits
                set a bit of another.

        """
        what = f'{field_type.name}.{name}'
        if name not in entry:
            raise ProtocolError(f'{self.alias}: invalid fields: {what} missing')
        value = entry[name]
        field = cast('BitmapField', schema.__fields__[name])
        if not isinstance(value, collections.abc.Mapping):
            raise ProtocolError(f'{self.alias}: invalid {what}: {value!r}, must be a mapping of its subfields')
        names = dict(field.subfields)
        if field.remainder is not None:
            names[field.remainder] = (0, 8 * field.length)
        out = {}  # type: dict[str, int]
        for sub, (_, size) in names.items():
            if sub not in value:
                raise ProtocolError(f'{self.alias}: invalid fields: {what}.{sub} missing')
            out[sub] = self._make_uint(value[sub], bits=size, name=f'{what}.{sub}')
        if field.remainder is not None and out[field.remainder] & ~field.remainder_mask:
            raise ProtocolError(f'{self.alias}: invalid {what}.{field.remainder}: {value[field.remainder]!r}, '
                                'sets a bit of another subfield')
        return out

    def _read_vendor_namespace(self, field_type: 'Enum_FieldType', fields: 'bytes', pos: 'int',
                               start: 'int') -> 'Optional[tuple[Data_VendorNamespace, int]]':
        """Decode a Vendor Namespace field and its vendor data.

        Args:
            field_type: type of the field
            fields: The field-data region.
            pos: Offset in ``fields`` where the field may start, before
                alignment.
            start: Offset of ``fields`` from the start of the header.

        Returns:
            The field, and the offset in ``fields`` just past its data;
            :obj:`None` if either runs past ``fields``.

        """
        size, _ = self._field_size(Schema_VendorNamespace)
        offset = pos + pad_length(start + pos, Schema_VendorNamespace.__align__)
        header = fields[offset:offset + size]
        if len(header) != size:
            return None
        schema = cast('Schema_VendorNamespace',
                      Schema_VendorNamespace.unpack(header, size, None))  # type: ignore[call-arg,misc]
        end = offset + size + schema.skip_length
        if end > len(fields):
            return None
        return Data_VendorNamespace(
            type=field_type,
            oui=schema.oui,
            sub_namespace=schema.sub_namespace,
            skip_length=schema.skip_length,
            data=fields[offset + size:end],
        ), end

    def _make_vendor_namespace(self, entry: 'Data_VendorNamespace | Mapping[str, Any]', pos: 'int') -> 'bytes':
        """Encode a Vendor Namespace field, the inverse of :meth:`_read_vendor_namespace`.

        Args:
            entry: The field, a data model or a mapping of its subfields; its
                ``skip_length`` may be left out.
            pos: Offset from the start of the header where the field may
                start, before alignment.

        Returns:
            The alignment padding, the field and its vendor data.

        Raises:
            ProtocolError: If ``oui`` is not 3 octets, ``data`` is not
                :class:`bytes`, ``skip_length`` is not its length, or a
                subfield does not fit.

        """
        field_type = cast('Enum_FieldType', Enum_FieldType.Vendor_Namespace)
        oui, data = self._make_vendor_data(field_type, Schema_VendorNamespace, entry)
        values = {**entry, 'skip_length': entry.get('skip_length', len(data))}
        if values['skip_length'] != len(data):
            raise ProtocolError(f'{self.alias}: invalid Vendor_Namespace.skip_length: {values["skip_length"]!r}, '
                                f'data has {len(data)} octets')
        schema = Schema_VendorNamespace(
            oui=oui,
            sub_namespace=self._make_subfield(field_type, Schema_VendorNamespace, values, 'sub_namespace'),
            skip_length=self._make_subfield(field_type, Schema_VendorNamespace, values, 'skip_length'),
        )
        return bytes(pad_length(pos, Schema_VendorNamespace.__align__)) + schema.pack() + data

    def _read_tlv_fields(self, field_type: 'Enum_FieldType', fields: 'bytes', pos: 'int',
                         start: 'int') -> 'Optional[tuple[Data_TLVFields, int]]':
        """Decode the TLV fields, which fill the rest of the field-data region.

        Args:
            field_type: type of the field
            fields: The field-data region.
            pos: Offset in ``fields`` where the TLV fields may start, before
                alignment.
            start: Offset of ``fields`` from the start of the header.

        Returns:
            The TLV fields, and the length of ``fields``; :obj:`None` if an
            item runs past ``fields``. Padding the end of ``fields`` cuts
            short is not required.

        """
        size, _ = self._field_size(Schema_TLV)
        offset = pos + pad_length(start + pos, Schema_TLV.__align__)
        if offset > len(fields):
            return None
        tlvs = []  # type: list[Data_TLV]
        while offset < len(fields):
            header = fields[offset:offset + size]
            if len(header) != size:
                return None
            schema = cast('Schema_TLV', Schema_TLV.unpack(header, size, None))  # type: ignore[call-arg,misc]
            data = fields[offset + size:offset + size + schema.length]
            if len(data) != schema.length:
                return None
            tlvs.append(Data_TLV(type=schema.type, length=schema.length,
                                 data=self._read_tlv_data(schema.type, data)))
            offset += size + len(data) + pad_length(len(data), Schema_TLV.__align__)
        return Data_TLVFields(type=field_type, tlvs=tuple(tlvs)), len(fields)

    def _make_tlv_fields(self, entry: 'Data_TLVFields | Mapping[str, Any]', pos: 'int') -> 'bytes':
        """Encode the TLV fields, the inverse of :meth:`_read_tlv_fields`.

        Args:
            entry: The TLV fields, a data model or a mapping whose ``tlvs``
                are data models or mappings of ``type``, ``data`` and,
                optionally, ``length``.
            pos: Offset from the start of the header where the TLV fields
                may start, before alignment.

        Returns:
            The alignment padding and the items, each padded.

        Raises:
            ProtocolError: If an item's ``length`` is not that of its data,
                or a subfield or its data does not encode.

        """
        out = bytearray(pad_length(pos, Schema_TLV.__align__))
        for item in entry.get('tlvs', ()):
            tlv_type = Enum_FieldType.get(item['type'])
            data = self._make_tlv_data(tlv_type, item['data'])
            if item.get('length', len(data)) != len(data):
                raise ProtocolError(f'{self.alias}: invalid TLV.length: {item["length"]!r}, '
                                    f'data has {len(data)} octets')
            values = {'type': tlv_type, 'length': len(data)}
            field_type = cast('Enum_FieldType', Enum_FieldType.TLV_fields_in_radiotap)
            out += Schema_TLV(
                type=self._make_subfield(field_type, Schema_TLV, values, 'type'),
                length=self._make_subfield(field_type, Schema_TLV, values, 'length'),
            ).pack()
            out += data + bytes(pad_length(len(data), Schema_TLV.__align__))
        return bytes(out)

    def _read_tlv_data(self, tlv_type: 'Enum_FieldType', data: 'bytes') -> 'Data_Field | Data_VendorTLV | bytes':
        """Decode a TLV item's data.

        Args:
            tlv_type: Type of the item.
            data: The item's data.

        Returns:
            A vendor TLV for the Vendor Namespace type, the field for a type
            whose schema ``data`` does not run past, and the raw octets
            otherwise. Data short of its schema, or of the vendor header, is
            read with the octets it lacks as zeros, and the result records the
            cut as ``__short_read__``, which :meth:`_make_tlv_data` replays;
            it stays raw if the zero-padding limits of
            :mod:`pcapkit.utilities.config` refuse the zeros.

        """
        # NOTE: radiotap.org reads the octets a producer leaves off an item as zeros, so short data is unpacked
        # at its schema's full length, to the end of a list item, and ``Schema.unpack`` records the cut (#2655).
        layout = None  # type: Optional[tuple[FieldParser, FieldConstructor, Type[Schema_Field]]]
        if tlv_type == Enum_FieldType.Vendor_Namespace:
            field_schema = Schema_VendorTLV  # type: Type[Schema]
            length, _ = self._field_size(field_schema)
            octets = data[:length]
        else:
            layout = self._lookup_field(tlv_type)
            if layout is None:
                return data
            field_schema = layout[2]
            size, rest = self._field_size(field_schema)
            if not rest and len(data) > size:
                return data
            length = max(len(data), size)
            if rest and len(data) > size:
                tail = next(field for field in field_schema.__fields__.values() if field.length < 0)
                item = tail._item_type if isinstance(tail, ListField) else None  # pylint: disable=protected-access
                if item is not None and item.length > 0:
                    length += -(len(data) - size) % item.length
            octets = data

        # NOTE: a limit on zero-padding, or a list taking the rest, may refuse
        # what it is given; the refusal is handled here, so it is quiet.
        with CaughtByCaller(FieldValueError):
            try:
                schema = cast('Schema', field_schema.unpack(octets, length, None))  # type: ignore[call-arg,misc]
            except FieldValueError:
                return data
        if layout is None:
            vendor = cast('Schema_VendorTLV', schema)
            entry = Data_VendorTLV(oui=vendor.oui, subtype=vendor.subtype, presence_type=vendor.presence_type,
                                   reserved=vendor.reserved, data=data[length:])  # type: Data_Field | Data_VendorTLV
        else:
            entry = layout[0](tlv_type, cast('Schema_Field', schema))

        record = schema.__dict__.get('__short_read__')
        if record is not None:
            entry.__update__({'__short_read__': record})
        return entry

    def _make_tlv_data(self, tlv_type: 'Enum_FieldType',
                       data: 'Data_Field | Data_VendorTLV | Mapping[str, Any] | bytes') -> 'bytes':
        """Encode a TLV item's data, the inverse of :meth:`_read_tlv_data`.

        Args:
            tlv_type: Type of the item.
            data: The item's data: raw octets, written as they are, or decoded,
                cut back as its ``__short_read__`` says when it has one.

        Returns:
            The item's data.

        Raises:
            ProtocolError: If decoded data is given for a type with no layout,
                or does not encode; if its ``__short_read__`` is not a field
                name and an octet count; or if a vendor TLV whose header is cut
                short has data.

        """
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if tlv_type == Enum_FieldType.Vendor_Namespace:
            oui, vendor_data = self._make_vendor_data(tlv_type, Schema_VendorTLV, data)
            values = {'reserved': 0, **data}
            header = self._pack_tlv_data(tlv_type, Schema_VendorTLV(
                oui=oui,
                subtype=self._make_subfield(tlv_type, Schema_VendorTLV, values, 'subtype'),
                presence_type=self._make_subfield(tlv_type, Schema_VendorTLV, values, 'presence_type'),
                reserved=self._make_subfield(tlv_type, Schema_VendorTLV, values, 'reserved'),
            ), data)
            if vendor_data and len(header) < self._field_size(Schema_VendorTLV)[0]:
                raise ProtocolError(f'{self.alias}: invalid VendorTLV.data: {vendor_data!r}, '
                                    'the vendor header before it is cut short')
            return header + vendor_data
        layout = self._lookup_field(tlv_type)
        if layout is None:
            raise ProtocolError(f'{self.alias}: invalid TLV.data: {tlv_type!r} defines no layout, '
                                'so its data must be bytes')
        return self._pack_tlv_data(tlv_type, layout[1](tlv_type, data), data)

    def _pack_tlv_data(self, tlv_type: 'Enum_FieldType', schema: 'Schema',
                       data: 'Data_Field | Data_VendorTLV | Mapping[str, Any]') -> 'bytes':
        """Pack a TLV item's schema, cut back as :meth:`_read_tlv_data` recorded.

        Args:
            tlv_type: Type of the item, for the error message.
            schema: The schema made from ``data``.
            data: The item's decoded data, whose ``__short_read__``, if any,
                names the field its octets ended inside and how many of that
                field's octets there were.

        Returns:
            The packed schema, without the octets past the cut.

        Raises:
            ProtocolError: If ``__short_read__`` is not a field of ``schema``
                and a count of octets.

        """
        record = data.get('__short_read__')
        if record is not None:
            if not (isinstance(record, (tuple, list)) and len(record) == 2 and record[0] in schema.__fields__
                    and isinstance(record[1], int) and not isinstance(record[1], bool) and record[1] >= 0):
                raise ProtocolError(f'{self.alias}: invalid {tlv_type.name}.__short_read__: {record!r}')
            # NOTE: ``Schema.pack`` cuts its buffers back to a record it holds.
            schema.__dict__['__short_read__'] = tuple(record)
        return schema.pack()

    def _make_vendor_data(self, field_type: 'Enum_FieldType', schema: 'Type[Schema]',
                          entry: 'Mapping[str, Any]') -> 'tuple[bytes, bytes]':
        """Check the OUI and the vendor data of a vendor namespace or a vendor TLV.

        Args:
            field_type: type of the field, for the error message
            schema: schema of the vendor header, whose ``oui`` the OUI fills
            entry: A data model or a mapping holding ``oui`` and ``data``,
                which may be left out for none.

        Returns:
            The OUI and the vendor data.

        Raises:
            ProtocolError: If ``oui`` is not as many octets as its field, or
                ``data`` is not :class:`bytes`.

        """
        what = 'VendorTLV' if schema is Schema_VendorTLV else field_type.name
        oui = entry.get('oui')
        size = schema.__fields__['oui'].length
        if not isinstance(oui, (bytes, bytearray)) or len(oui) != size:
            raise ProtocolError(f'{self.alias}: invalid {what}.oui: {oui!r}, must be {size} octets')
        data = entry.get('data', b'')
        if not isinstance(data, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid {what}.data: {data!r}, must be bytes')
        return bytes(oui), bytes(data)
