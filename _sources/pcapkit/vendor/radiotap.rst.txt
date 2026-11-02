======================================================================
:class:`~pcapkit.protocols.link.radiotap.Radiotap` Vendor Crawlers
======================================================================

.. module:: pcapkit.vendor.radiotap

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.radiotap.Radiotap` implementations, each scraping
radiotap.org [*]_. Available vendor crawlers include:

.. list-table::

   * - :class:`Radiotap_FieldType <pcapkit.vendor.radiotap.field_type.FieldType>`
     - Field Types
   * - :class:`Radiotap_Flags <pcapkit.vendor.radiotap.flags.Flags>`
     - Flags
   * - :class:`Radiotap_ChannelFlags <pcapkit.vendor.radiotap.channel_flags.ChannelFlags>`
     - Channel Flags
   * - :class:`Radiotap_RXFlags <pcapkit.vendor.radiotap.rx_flags.RXFlags>`
     - RX Flags
   * - :class:`Radiotap_TXFlags <pcapkit.vendor.radiotap.tx_flags.TXFlags>`
     - TX Flags
   * - :class:`Radiotap_MCSKnown <pcapkit.vendor.radiotap.mcs_known.MCSKnown>`
     - MCS Known Flags
   * - :class:`Radiotap_AMPDUFlags <pcapkit.vendor.radiotap.ampdu_flags.AMPDUFlags>`
     - A-MPDU Status Flags
   * - :class:`Radiotap_VHTKnown <pcapkit.vendor.radiotap.vht_known.VHTKnown>`
     - VHT Known Flags
   * - :class:`Radiotap_VHTFlags <pcapkit.vendor.radiotap.vht_flags.VHTFlags>`
     - VHT Flags
   * - :class:`Radiotap_VHTCoding <pcapkit.vendor.radiotap.vht_coding.VHTCoding>`
     - VHT Coding Flags
   * - :class:`Radiotap_TimestampFlags <pcapkit.vendor.radiotap.timestamp_flags.TimestampFlags>`
     - Timestamp Flags
   * - :class:`Radiotap_HEMUOtherUserKnown <pcapkit.vendor.radiotap.he_mu_other_user_known.HEMUOtherUserKnown>`
     - HE-MU-other-user Known Flags
   * - :class:`Radiotap_LSIGData1 <pcapkit.vendor.radiotap.lsig_data1.LSIGData1>`
     - L-SIG Data1 Flags
   * - :class:`Radiotap_S1GKnown <pcapkit.vendor.radiotap.s1g_known.S1GKnown>`
     - S1G Known Flags
   * - :class:`Radiotap_EHTKnown <pcapkit.vendor.radiotap.eht_known.EHTKnown>`
     - EHT Known Flags

.. versionadded:: 1.6.0

Field Types
===========

.. module:: pcapkit.vendor.radiotap.field_type

This module contains the vendor crawler for **Radiotap Field Types**,
which is automatically generating :class:`pcapkit.const.radiotap.field_type.FieldType`.

The registry is radiotap.org's *Defined Fields* table, scraped from
:attr:`~pcapkit.vendor.radiotap.field_type.FieldType.LINK`, and RTS retries and data
retries from its *Unofficially Used Fields* table, scraped from
:data:`~pcapkit.vendor.radiotap.field_type.UNOFFICIAL_LINK`. A bit number is also a
TLV type, so the TLV-only fields from 32 on are in it too. The tables name no
reserved value: ``_missing_`` resolves bits 29, 30 and 31 of every extended
presence word to ``Reserved``, as radiotap.org's introduction reserves them, and
every other value to ``Unassigned``.

.. autoclass:: pcapkit.vendor.radiotap.field_type.FieldType
   :members: FLAG, LINK
   :show-inheritance:

.. autodata:: pcapkit.vendor.radiotap.field_type.UNOFFICIAL_LINK

.. autodata:: pcapkit.vendor.radiotap.field_type.UNOFFICIAL

Flags
=====

.. module:: pcapkit.vendor.radiotap.flags

This module contains the vendor crawler for **Radiotap Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.flags.Flags`.

Each flag crawler scrapes the table on its field's page, and subclasses this one.
A row whose mask sets one bit is a member; a row that sets more bits, or that
radiotap.org marks reserved or unused, is not, and its bits stay undefined. A
member's name is the macro the crawler's ``NAMES`` gives its bit, less the
``IEEE80211_RADIOTAP_`` or ``IEEE80211_`` prefix: the Linux kernel's, from
``include/net/ieee80211_radiotap.h``, or Wireshark's where Linux names none.
Neither names the HE-MU-other-user bits, which take radiotap.org's wording.

.. autoclass:: pcapkit.vendor.radiotap.flags.Flags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

Channel Flags
=============

.. module:: pcapkit.vendor.radiotap.channel_flags

This module contains the vendor crawler for **Radiotap Channel Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.channel_flags.ChannelFlags`.

.. autoclass:: pcapkit.vendor.radiotap.channel_flags.ChannelFlags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

RX Flags
========

.. module:: pcapkit.vendor.radiotap.rx_flags

This module contains the vendor crawler for **Radiotap RX Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.rx_flags.RXFlags`.

.. autoclass:: pcapkit.vendor.radiotap.rx_flags.RXFlags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

TX Flags
========

.. module:: pcapkit.vendor.radiotap.tx_flags

This module contains the vendor crawler for **Radiotap TX Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.tx_flags.TXFlags`.

.. autoclass:: pcapkit.vendor.radiotap.tx_flags.TXFlags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

MCS Known Flags
===============

.. module:: pcapkit.vendor.radiotap.mcs_known

This module contains the vendor crawler for **Radiotap MCS Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.mcs_known.MCSKnown`.

.. autoclass:: pcapkit.vendor.radiotap.mcs_known.MCSKnown
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

A-MPDU Status Flags
===================

.. module:: pcapkit.vendor.radiotap.ampdu_flags

This module contains the vendor crawler for **Radiotap A-MPDU Status Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.ampdu_flags.AMPDUFlags`.

.. autoclass:: pcapkit.vendor.radiotap.ampdu_flags.AMPDUFlags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

VHT Known Flags
===============

.. module:: pcapkit.vendor.radiotap.vht_known

This module contains the vendor crawler for **Radiotap VHT Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.vht_known.VHTKnown`.

.. autoclass:: pcapkit.vendor.radiotap.vht_known.VHTKnown
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

VHT Flags
=========

.. module:: pcapkit.vendor.radiotap.vht_flags

This module contains the vendor crawler for **Radiotap VHT Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.vht_flags.VHTFlags`.

.. autoclass:: pcapkit.vendor.radiotap.vht_flags.VHTFlags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

VHT Coding Flags
================

.. module:: pcapkit.vendor.radiotap.vht_coding

This module contains the vendor crawler for **Radiotap VHT Coding Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.vht_coding.VHTCoding`.

.. autoclass:: pcapkit.vendor.radiotap.vht_coding.VHTCoding
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

Timestamp Flags
===============

.. module:: pcapkit.vendor.radiotap.timestamp_flags

This module contains the vendor crawler for **Radiotap Timestamp Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.timestamp_flags.TimestampFlags`.

.. autoclass:: pcapkit.vendor.radiotap.timestamp_flags.TimestampFlags
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

HE-MU-other-user Known Flags
============================

.. module:: pcapkit.vendor.radiotap.he_mu_other_user_known

This module contains the vendor crawler for **Radiotap HE-MU-other-user Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.he_mu_other_user_known.HEMUOtherUserKnown`.

.. autoclass:: pcapkit.vendor.radiotap.he_mu_other_user_known.HEMUOtherUserKnown
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

L-SIG Data1 Flags
=================

.. module:: pcapkit.vendor.radiotap.lsig_data1

This module contains the vendor crawler for **Radiotap L-SIG Data1 Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.lsig_data1.LSIGData1`.

.. autoclass:: pcapkit.vendor.radiotap.lsig_data1.LSIGData1
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

S1G Known Flags
===============

.. module:: pcapkit.vendor.radiotap.s1g_known

This module contains the vendor crawler for **Radiotap S1G Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.s1g_known.S1GKnown`.

.. autoclass:: pcapkit.vendor.radiotap.s1g_known.S1GKnown
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

EHT Known Flags
===============

.. module:: pcapkit.vendor.radiotap.eht_known

This module contains the vendor crawler for **Radiotap EHT Known Flags**,
which is automatically generating :class:`pcapkit.const.radiotap.eht_known.EHTKnown`.

.. autoclass:: pcapkit.vendor.radiotap.eht_known.EHTKnown
   :members: FLAG, LINK, SUBFIELD, NAMES
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.radiotap.org/fields/defined, its unofficial-fields
   page and each field's own page.
