Radiotap - IEEE 802.11 Radiotap Header
========================================

.. module:: pcapkit.protocols.link.radiotap
.. module:: pcapkit.protocols.link.radiotap.protocol

:mod:`pcapkit.protocols.link.radiotap.protocol` contains
:class:`~pcapkit.protocols.link.radiotap.protocol.Radiotap`
only, which implements the extractor for the radiotap header [*]_ capture
tools prepend to an 802.11 frame, as seen on a
``LINKTYPE_IEEE802_11_RADIOTAP`` capture, or on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_IEEE80211_RADIOTAP``. Radiotap is not part of the 802.11 standard.
Its fixed start, all little-endian, is:

.. table::

   ====== ==== ======================== ================================
   Octets Bits Name                     Description
   ====== ==== ======================== ================================
   0      0    ``radiotap.it_version``  Header Revision (always ``0``)
   1      8    ``radiotap.it_pad``      Padding
   2      16   ``radiotap.it_len``      Header Length (header included)
   4      32   ``radiotap.it_present``  First Present-Flags Word
   ====== ==== ======================== ================================

followed by a chain of further present-flags words -- bit 31 of a word
signals that another follows -- and then the optional-field region those
bitmasks select, each field aligned and sized per its own type. ``it_len``
bounds the whole of it; the 802.11 MAC frame starts at that offset.

.. versionadded:: 1.6.0

Scope
-----

This class:

* **Decodes** the fixed 8-octet start -- ``it_version``, ``it_pad``,
  ``it_len`` -- and walks the present-flags chain, recording every word as
  :attr:`~pcapkit.protocols.link.radiotap.data.Radiotap.present`.
* **Keeps** the optional-field region those bits select whole, as
  :attr:`~pcapkit.protocols.link.radiotap.data.Radiotap.fields`, which is
  what a rebuild from the data model writes, and **decodes** it as
  :attr:`~pcapkit.protocols.link.radiotap.data.Radiotap.decoded`, by the
  rules below.
* **Hands** everything from ``it_len`` on, the 802.11 MAC frame, to
  :class:`~pcapkit.protocols.link.ieee802_11.protocol.IEEE802_11`
  (:class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` when nothing follows).
  The header names no next protocol, since an 802.11 frame always follows it,
  so the frame is looked up in
  :attr:`Radiotap.__proto__ <pcapkit.protocols.link.radiotap.protocol.Radiotap.__proto__>`
  under :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`;
  :func:`~pcapkit.foundation.registry.protocols.link.register_radiotap` replaces
  the entry.

Field Decoding
--------------

The bits are walked in order, word by word, and the fields they select follow
one another in the same order, each aligned to its own boundary counted from
the start of the header. A field type is read and made by the methods
:attr:`Radiotap.__field__ <pcapkit.protocols.link.radiotap.protocol.Radiotap.__field__>`
names for it, through the schema the
:class:`~pcapkit.protocols.link.radiotap.schema.RadiotapField` registry holds
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
  ``__short_read__``, as :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
  does, so :meth:`Radiotap.make <pcapkit.protocols.link.radiotap.protocol.Radiotap.make>`
  writes the octets that were captured.
* **What is not decoded.** A radiotap-namespace bit no field is defined for --
  18, FreeBSD's XChannel, which radiotap.org lists as unofficial, and every one
  numbered 32 or more, the TLV-only types included -- or a field that runs
  past the region, ends the walk, since nothing after it can be located: an
  :class:`~pcapkit.protocols.link.radiotap.data.Unknown` entry keeps every
  octet from there on, and its ``reason`` says which of the two it was.

Each bit with data in the radiotap namespace, and each namespace field, has
one entry in :attr:`~pcapkit.protocols.link.radiotap.data.Radiotap.decoded`,
keyed by its :class:`~pcapkit.const.radiotap.field_type.FieldType`; the
subfields keep radiotap.org's names.
:meth:`~pcapkit.protocols.link.radiotap.protocol.Radiotap.make` takes the same entries
as ``fields`` and encodes them with zero padding.

.. autoclass:: pcapkit.protocols.link.radiotap.protocol.Radiotap
   :no-members:
   :show-inheritance:

   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: __proto_key__
      :no-value:

   .. autoattribute:: __field__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make
   .. automethod:: register
   .. automethod:: register_field

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_radiotap_fields
   .. automethod:: _make_radiotap_fields
   .. automethod:: _read_field_unknown
   .. automethod:: _read_field_tsft
   .. automethod:: _read_field_flags
   .. automethod:: _read_field_rate
   .. automethod:: _read_field_channel
   .. automethod:: _read_field_fhss
   .. automethod:: _read_field_antenna_signal
   .. automethod:: _read_field_antenna_noise
   .. automethod:: _read_field_lock_quality
   .. automethod:: _read_field_tx_attenuation
   .. automethod:: _read_field_db_tx_attenuation
   .. automethod:: _read_field_dbm_tx_power
   .. automethod:: _read_field_antenna
   .. automethod:: _read_field_db_antenna_signal
   .. automethod:: _read_field_db_antenna_noise
   .. automethod:: _read_field_rx_flags
   .. automethod:: _read_field_tx_flags
   .. automethod:: _read_field_rts_retries
   .. automethod:: _read_field_data_retries
   .. automethod:: _read_field_mcs
   .. automethod:: _read_field_ampdu_status
   .. automethod:: _read_field_vht
   .. automethod:: _read_field_timestamp
   .. automethod:: _read_field_he
   .. automethod:: _read_field_he_mu
   .. automethod:: _read_field_he_mu_other_user
   .. automethod:: _read_field_zero_length_psdu
   .. automethod:: _read_field_lsig
   .. automethod:: _read_field_s1g
   .. automethod:: _read_field_usig
   .. automethod:: _read_field_eht
   .. automethod:: _make_field_unknown
   .. automethod:: _make_field_tsft
   .. automethod:: _make_field_flags
   .. automethod:: _make_field_rate
   .. automethod:: _make_field_channel
   .. automethod:: _make_field_fhss
   .. automethod:: _make_field_antenna_signal
   .. automethod:: _make_field_antenna_noise
   .. automethod:: _make_field_lock_quality
   .. automethod:: _make_field_tx_attenuation
   .. automethod:: _make_field_db_tx_attenuation
   .. automethod:: _make_field_dbm_tx_power
   .. automethod:: _make_field_antenna
   .. automethod:: _make_field_db_antenna_signal
   .. automethod:: _make_field_db_antenna_noise
   .. automethod:: _make_field_rx_flags
   .. automethod:: _make_field_tx_flags
   .. automethod:: _make_field_rts_retries
   .. automethod:: _make_field_data_retries
   .. automethod:: _make_field_mcs
   .. automethod:: _make_field_ampdu_status
   .. automethod:: _make_field_vht
   .. automethod:: _make_field_timestamp
   .. automethod:: _make_field_he
   .. automethod:: _make_field_he_mu
   .. automethod:: _make_field_he_mu_other_user
   .. automethod:: _make_field_zero_length_psdu
   .. automethod:: _make_field_lsig
   .. automethod:: _make_field_s1g
   .. automethod:: _make_field_usig
   .. automethod:: _make_field_eht
   .. automethod:: _get_payload

Header Schemas
--------------

.. module:: pcapkit.protocols.link.radiotap.schema

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Radiotap
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.RadiotapField
   :members:
   :show-inheritance:

   .. autoattribute:: __align__

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.TSFT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Rate
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Channel
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.FHSS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.AntennaSignal
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.AntennaNoise
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.LockQuality
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.TXAttenuation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.DBTXAttenuation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.DBmTXPower
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Antenna
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.DBAntennaSignal
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.DBAntennaNoise
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.RXFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.TXFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.RTSRetries
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.DataRetries
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.MCS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.AMPDUStatus
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.VHT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.HE
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.HEMU
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.HEMUOtherUser
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.ZeroLengthPSDU
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.LSIG
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.VendorNamespace
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.S1G
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.USIG
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.EHT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.TLV
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.schema.VendorTLV
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.radiotap.data

.. autoclass:: pcapkit.protocols.link.radiotap.data.Radiotap
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.RadiotapField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.TSFT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.Rate
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.Channel
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.FHSS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.AntennaSignal
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.AntennaNoise
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.LockQuality
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.TXAttenuation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.DBTXAttenuation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.DBmTXPower
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.Antenna
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.DBAntennaSignal
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.DBAntennaNoise
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.RXFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.TXFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.RTSRetries
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.DataRetries
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.MCS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.MCSFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.AMPDUStatus
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.VHT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HE
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HEData1
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HEData2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HEMU
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HEMUFlags1
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HEMUFlags2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.HEMUOtherUser
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.ZeroLengthPSDU
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.LSIG
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.TLVFields
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.RadiotapNamespace
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.VendorNamespace
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.S1G
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.USIG
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.USIGCommon
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.EHT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.TLV
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.radiotap.data.VendorTLV
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] <https://www.radiotap.org/>, its field pages and its
   ``radiotap-library``; the Linux kernel's
   ``include/net/ieee80211_radiotap.h`` and ``net/wireless/radiotap.c``; and
   Wireshark's ``packet-ieee80211-radiotap.c`` and
   ``packet-ieee80211-radiotap-iter.c``.
