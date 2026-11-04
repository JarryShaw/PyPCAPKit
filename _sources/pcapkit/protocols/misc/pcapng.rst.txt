===================
PCAP-NG File Format
===================

.. module:: pcapkit.protocols.misc.pcapng
.. module:: pcapkit.protocols.misc.pcapng.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.misc.pcapng.PacketDirection``,
   ``pcapkit.protocols.misc.pcapng.PacketReception`` and
   ``pcapkit.protocols.misc.pcapng.WireGuardKeyLabel``, with no alias: they are in this
   module, and :mod:`pcapkit.protocols.misc.pcapng` exports the protocol class alone
   (:issue:`2534`). ``pcapkit.protocols.misc.pcapng.PAT_EUI_ADDR`` and
   ``pcapkit.protocols.misc.pcapng.PAT_MAC_ADDR``, with no alias:
   :meth:`~pcapkit.protocols.protocol.Protocol._read_mac_addr` and
   :meth:`~pcapkit.protocols.protocol.Protocol._make_mac_addr` read and make the address
   (:issue:`2614`).

:mod:`pcapkit.protocols.misc.pcapng.protocol` contains
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`,
which implements an extractor for PCAP-NG file format [*]_, and the
:class:`~pcapkit.protocols.misc.pcapng.protocol.PacketDirection`,
:class:`~pcapkit.protocols.misc.pcapng.protocol.PacketReception` and
:class:`~pcapkit.protocols.misc.pcapng.protocol.WireGuardKeyLabel` enumerations.

.. versionchanged:: 1.5.0

   A block rebuilds as it was parsed, byte for byte: its lengths, padding,
   byte order, flag bits and repeated options are kept, and so is a block
   that is unknown, malformed, shorter than its fixed fields or cut short
   (:issue:`1272`, :issue:`1273`, :issue:`1276`, :issue:`1277`,
   :issue:`1278`, :issue:`1279`, :issue:`1280`, :issue:`1281`,
   :issue:`1282`, :issue:`1283`, :issue:`1284`, :issue:`1382`,
   :issue:`1383`, :issue:`1384`, :issue:`1405`, :issue:`1413`,
   :issue:`1414`, :issue:`1422`, :issue:`1470`). A packet block keeps the
   octets it captured (:issue:`646`); an option running past its block's
   option area leaves the whole area kept as captured in ``options_raw``,
   with a :exc:`~pcapkit.utilities.warnings.ProtocolWarning`, where it was
   read as zeros (:issue:`594`, :issue:`1325`); a truncated capture does not
   raise :exc:`ValueError` (:issue:`678`); and ``timestamp_epoch`` is not
   shifted by the host's timezone (:issue:`361`).

.. autoclass:: pcapkit.protocols.misc.pcapng.protocol.PCAPNG
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: section_context
   .. autoproperty:: byteorder
   .. autoproperty:: nanosecond
   .. autoproperty:: ts_resolution
   .. autoproperty:: ts_offset
   .. autoproperty:: ts_timezone
   .. autoproperty:: linktype
   .. autoproperty:: block
   .. autoproperty:: packet

   .. automethod:: register
   .. automethod:: register_block
   .. automethod:: register_option
   .. automethod:: register_record
   .. automethod:: register_secrets

   .. automethod:: unpack
   .. automethod:: pack

   .. automethod:: read
   .. automethod:: make

   .. automethod:: index

   .. automethod:: _decode_next_layer
   .. automethod:: _dispatch_linktype

   .. automethod:: _get_payload
   .. automethod:: _make_data

   .. automethod:: _read_block_unknown
   .. automethod:: _read_block_shb
   .. automethod:: _read_block_idb
   .. automethod:: _read_block_epb
   .. automethod:: _read_block_spb
   .. automethod:: _read_block_nrb
   .. automethod:: _read_block_isb
   .. automethod:: _read_block_systemd
   .. automethod:: _read_block_dsb
   .. automethod:: _read_block_cb
   .. automethod:: _read_block_packet

   .. automethod:: _read_pcapng_options
   .. automethod:: _read_option_unknown
   .. automethod:: _read_option_endofopt
   .. automethod:: _read_option_comment
   .. automethod:: _read_option_custom
   .. automethod:: _read_option_if_name
   .. automethod:: _read_option_if_description
   .. automethod:: _read_option_if_ipv4
   .. automethod:: _read_option_if_ipv6
   .. automethod:: _read_option_if_mac
   .. automethod:: _read_option_if_eui
   .. automethod:: _read_option_if_speed
   .. automethod:: _read_option_if_tsresol
   .. automethod:: _read_option_if_tzone
   .. automethod:: _read_option_if_filter
   .. automethod:: _read_option_if_os
   .. automethod:: _read_option_if_fcslen
   .. automethod:: _read_option_if_tsoffset
   .. automethod:: _read_option_if_hardware
   .. automethod:: _read_option_if_txspeed
   .. automethod:: _read_option_if_rxspeed
   .. automethod:: _read_option_epb_flags
   .. automethod:: _read_option_epb_hash
   .. automethod:: _read_option_epb_dropcount
   .. automethod:: _read_option_epb_packetid
   .. automethod:: _read_option_epb_queue
   .. automethod:: _read_option_epb_verdict
   .. automethod:: _read_option_ns_dnsname
   .. automethod:: _read_option_ns_dnsipv4
   .. automethod:: _read_option_ns_dnsipv6
   .. automethod:: _read_option_isb_starttime
   .. automethod:: _read_option_isb_endtime
   .. automethod:: _read_option_isb_ifrecv
   .. automethod:: _read_option_isb_ifdrop
   .. automethod:: _read_option_isb_filteraccept
   .. automethod:: _read_option_isb_osdrop
   .. automethod:: _read_option_isb_usrdeliv
   .. automethod:: _read_option_pack_flags
   .. automethod:: _read_option_pack_hash

   .. automethod:: _read_nrb_records
   .. automethod:: _read_record_unknown
   .. automethod:: _read_record_end
   .. automethod:: _read_record_ipv4
   .. automethod:: _read_record_ipv6

   .. automethod:: _read_secrets_unknown
   .. automethod:: _read_secrets_tls
   .. automethod:: _read_secrets_wireguard
   .. automethod:: _read_secrets_zigbee_nwk
   .. automethod:: _read_secrets_zigbee_aps

   .. automethod:: _make_block_unknown
   .. automethod:: _make_block_shb
   .. automethod:: _make_block_idb
   .. automethod:: _make_block_epb
   .. automethod:: _make_block_spb
   .. automethod:: _make_block_nrb
   .. automethod:: _make_block_isb
   .. automethod:: _make_block_systemd
   .. automethod:: _make_block_dsb
   .. automethod:: _make_block_cb
   .. automethod:: _make_block_packet

   .. automethod:: _make_pcapng_options
   .. automethod:: _make_option_unknown
   .. automethod:: _make_option_endofopt
   .. automethod:: _make_option_comment
   .. automethod:: _make_option_custom
   .. automethod:: _make_option_if_name
   .. automethod:: _make_option_if_description
   .. automethod:: _make_option_if_ipv4
   .. automethod:: _make_option_if_ipv6
   .. automethod:: _make_option_if_mac
   .. automethod:: _make_option_if_eui
   .. automethod:: _make_option_if_speed
   .. automethod:: _make_option_if_tsresol
   .. automethod:: _make_option_if_tzone
   .. automethod:: _make_option_if_filter
   .. automethod:: _make_option_if_os
   .. automethod:: _make_option_if_fcslen
   .. automethod:: _make_option_if_tsoffset
   .. automethod:: _make_option_if_hardware
   .. automethod:: _make_option_if_txspeed
   .. automethod:: _make_option_if_rxspeed
   .. automethod:: _make_option_epb_flags
   .. automethod:: _make_option_epb_hash
   .. automethod:: _make_option_epb_dropcount
   .. automethod:: _make_option_epb_packetid
   .. automethod:: _make_option_epb_queue
   .. automethod:: _make_option_epb_verdict
   .. automethod:: _make_option_ns_dnsname
   .. automethod:: _make_option_ns_dnsipv4
   .. automethod:: _make_option_ns_dnsipv6
   .. automethod:: _make_option_isb_starttime
   .. automethod:: _make_option_isb_endtime
   .. automethod:: _make_option_isb_ifrecv
   .. automethod:: _make_option_isb_ifdrop
   .. automethod:: _make_option_isb_filteraccept
   .. automethod:: _make_option_isb_osdrop
   .. automethod:: _make_option_isb_usrdeliv
   .. automethod:: _make_option_pack_flags
   .. automethod:: _make_option_pack_hash

   .. automethod:: _make_nrb_records
   .. automethod:: _make_record_unknown
   .. automethod:: _make_record_end
   .. automethod:: _make_record_ipv4
   .. automethod:: _make_record_ipv6

   .. automethod:: _make_secrets_unknown
   .. automethod:: _make_secrets_tls
   .. automethod:: _make_secrets_wireguard
   .. automethod:: _make_secrets_zigbee_nwk
   .. automethod:: _make_secrets_zigbee_aps

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:
   .. autoattribute:: __block__
      :no-value:
   .. autoattribute:: __option__
      :no-value:
   .. autoattribute:: __record__
      :no-value:
   .. autoattribute:: __secrets__
      :no-value:

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoattribute:: PACKET_TYPES
   .. autoattribute:: SHORT_HEADER_TYPES
   .. automethod:: _get_timezone
   .. automethod:: _read_block_short
   .. automethod:: _read_block_short_header
   .. automethod:: _make_block_short
   .. automethod:: _make_mac_addr

   .. automethod:: _check_block_floor
   .. automethod:: __length_hint__

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.misc.pcapng.protocol.PacketDirection
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.protocol.PacketReception
   :members:
   :undoc-members:
   :show-inheritance:

:class:`TLSKeyLabel <pcapkit.const.pcapng.tls_key_label.TLSKeyLabel>` is defined
in :mod:`pcapkit.const.pcapng.tls_key_label`, generated like its
:mod:`pcapkit.const.pcapng` siblings because :rfc:`9850#section-4.2` makes it an
IANA registry.

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.misc.pcapng.TLSKeyLabel``, with no alias; use
   :class:`pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` instead
   (:issue:`886`, :issue:`1744`).

.. autoclass:: pcapkit.protocols.misc.pcapng.protocol.WireGuardKeyLabel
   :members:
   :undoc-members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.misc.pcapng.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.misc.pcapng``, with no alias: the module moved here
   (:issue:`2534`).

.. autodata:: pcapkit.protocols.misc.pcapng.schema.BYTE_ORDER_MAGIC

.. autodata:: pcapkit.protocols.misc.pcapng.schema.GENERIC_BLOCK_MINIMUM

.. autodata:: pcapkit.protocols.misc.pcapng.schema.BLOCK_MINIMUM
   :no-value:

.. autodata:: pcapkit.protocols.misc.pcapng.schema.DEFAULT_RESOLUTION

.. autodata:: pcapkit.protocols.misc.pcapng.schema.PACKET_FLAGS
   :no-value:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.PCAPNG
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.BlockType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.UnknownBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.SectionHeaderBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.InterfaceDescriptionBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EnhancedPacketBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.SimplePacketBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.NameResolutionBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.InterfaceStatisticsBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.SystemdJournalExportBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.DecryptionSecretsBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.CustomBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.PacketBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.Option
   :members:
   :show-inheritance:
   :special-members: __enum__

.. autoclass:: pcapkit.protocols.misc.pcapng.schema._OPT_Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.UnknownOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EndOfOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.CommentOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.CustomOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema._IF_Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_NameOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_DescriptionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_IPv4AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_IPv6AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_MACAddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_EUIAddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_SpeedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_TSResolOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_TZoneOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_FilterOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_OSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_FCSLenOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_TSOffsetOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_HardwareOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_TxSpeedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IF_RxSpeedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema._EPB_Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPB_FlagsOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPB_HashOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPB_DropCountOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPB_PacketIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPB_QueueOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPB_VerdictOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema._NS_Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.NS_DNSNameOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.NS_DNSIP4AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.NS_DNSIP6AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema._ISB_Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_StartTimeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_EndTimeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_IFRecvOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_IFDropOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_FilterAcceptOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_OSDropOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ISB_UsrDelivOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema._PACK_Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.PACK_FlagsOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.PACK_HashOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.NameResolutionRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.UnknownRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EndRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IPv4Record
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.IPv6Record
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.DSBSecrets
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.UnknownSecrets
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.TLSKeyLog
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.WireGuardKeyLog
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ZigBeeNWKKey
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ZigBeeAPSKey
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.FlagsField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.OptionEnumField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.OptionAreaField
   :members:
   :show-inheritance:

Type Stubs
----------

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ByteorderTest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.ResolutionData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.EPBFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.schema.PACKFlags
   :members:
   :show-inheritance:

Auxiliary Functions
-------------------

The byte order of every block but the Section Header Block is read by
:func:`~pcapkit.corekit.schema.byteorder.byteorder_callback`, which is
shared with the PCAP frame header and documented in
:mod:`pcapkit.corekit.schema.byteorder`.

.. autofunction:: pcapkit.protocols.misc.pcapng.schema.shb_byteorder_callback
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.pcapng_block_selector
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.dsb_secrets_selector

.. autofunction:: pcapkit.protocols.misc.pcapng.schema.nonnegative
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.held_body
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.bounded_option
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.bounded_area
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.captured_area
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.secrets_area
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.zigbee_key_has_trailing
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.zigbee_key_trailing
.. autofunction:: pcapkit.protocols.misc.pcapng.schema.zigbee_key_held
.. autofunction:: pcapkit.protocols.misc.pcapng.schema._spb_data_length
.. autofunction:: pcapkit.protocols.misc.pcapng.schema._cut_last_line
.. autofunction:: pcapkit.protocols.misc.pcapng.schema._malformed_line_message

Data Models
-----------

.. module:: pcapkit.protocols.misc.pcapng.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.misc.pcapng``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.misc.pcapng.data.PCAPNG
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.UnknownBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.SectionHeaderBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.InterfaceDescriptionBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EnhancedPacketBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.SimplePacketBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.NameResolutionBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.InterfaceStatisticsBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.SystemdJournalExportBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.DecryptionSecretsBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.CustomBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.PacketBlock
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.UnknownOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EndOfOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.CommentOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.CustomOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_NameOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_DescriptionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_IPv4AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_IPv6AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_MACAddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_EUIAddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_SpeedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_TSResolOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_TZoneOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_FilterOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_OSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_FCSLenOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_TSOffsetOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_HardwareOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_TxSpeedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IF_RxSpeedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EPB_FlagsOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EPB_HashOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EPB_DropCountOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EPB_PacketIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EPB_QueueOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EPB_VerdictOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.NS_DNSNameOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.NS_DNSIP4AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.NS_DNSIP6AddrOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_StartTimeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_EndTimeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_IFRecvOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_IFDropOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_FilterAcceptOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_OSDropOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ISB_UsrDelivOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.PACK_FlagsOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.PACK_HashOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.NameResolutionRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.UnknownRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.EndRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IPv4Record
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.IPv6Record
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.DSBSecrets
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.UnknownSecrets
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.TLSKeyLogEntries
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.TLSKeyLog
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.WireGuardKeyLog
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ZigBeeNWKKey
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.data.ZigBeeAPSKey
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html
