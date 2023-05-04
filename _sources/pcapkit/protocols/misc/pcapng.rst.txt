===================
PCAP-NG File Format
===================

.. module:: pcapkit.protocols.misc.pcapng

:mod:`pcapkit.protocols.misc.pcapng` contains
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` only,
which implements extractor for PCAP-NG file format [*]_.

.. autoclass:: pcapkit.protocols.misc.pcapng.PCAPNG
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: context
   .. autoproperty:: byteorder
   .. autoproperty:: nanosecond
   .. autoproperty:: ts_resolution
   .. autoproperty:: ts_offset
   .. autoproperty:: ts_timezone
   .. autoproperty:: linktype
   .. autoproperty:: block

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

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.misc.pcapng.PacketDirection
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.PacketReception
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.TLSKeyLabel
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcapng.WireGuardKeyLabel
   :members:
   :undoc-members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.misc.pcapng

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.PCAPNG
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.BlockType
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.UnknownBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.SectionHeaderBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.InterfaceDescriptionBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EnhancedPacketBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.SimplePacketBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.NameResolutionBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.InterfaceStatisticsBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.SystemdJournalExportBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.DecryptionSecretsBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.CustomBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.PacketBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng._OPT_Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.UnknownOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EndOfOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.CommentOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.CustomOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng._IF_Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_NameOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_DescriptionOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_IPv4AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_IPv6AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_MACAddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_EUIAddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_SpeedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_TSResolOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_TZoneOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_FilterOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_OSOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_FCSLenOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_TSOffsetOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_HardwareOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_TxSpeedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IF_RxSpeedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng._EPB_Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPB_FlagsOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPB_HashOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPB_DropCountOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPB_PacketIDOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPB_QueueOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPB_VerdictOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng._NS_Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.NS_DNSNameOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.NS_DNSIP4AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.NS_DNSIP6AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng._ISB_Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_StartTimeOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_EndTimeOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_IFRecvOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_IFDropOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_FilterAcceptOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_OSDropOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ISB_UsrDelivOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng._PACK_Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.PACK_FlagsOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.PACK_HashOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.NameResolutionRecord
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.UnknownRecord
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EndRecord
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IPv4Record
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.IPv6Record
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.DSBSecrets
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.UnknownSecrets
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.TLSKeyLog
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.WireGuardKeyLog
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ZigBeeNWKKey
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ZigBeeAPSKey
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Type Stubs
----------

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ByteorderTest
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.ResolutionData
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.EPBFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.misc.pcapng.PACKFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.protocols.schema.misc.pcapng.byteorder_callback
.. autofunction:: pcapkit.protocols.schema.misc.pcapng.shb_byteorder_callback
.. autofunction:: pcapkit.protocols.schema.misc.pcapng.pcapng_block_selector
.. autofunction:: pcapkit.protocols.schema.misc.pcapng.dsb_secrets_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.misc.pcapng

.. autoclass:: pcapkit.protocols.data.misc.pcapng.PCAPNG
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.UnknownBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.SectionHeaderBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.InterfaceDescriptionBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EnhancedPacketBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.SimplePacketBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.NameResolutionBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.InterfaceStatisticsBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.SystemdJournalExportBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.DecryptionSecretsBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.CustomBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.PacketBlock
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.UnknownOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EndOfOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.CommentOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.CustomOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_NameOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_DescriptionOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_IPv4AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_IPv6AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_MACAddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_EUIAddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_SpeedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_TSResolOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_TZoneOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_FilterOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_OSOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_FCSLenOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_TSOffsetOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_HardwareOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_TxSpeedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IF_RxSpeedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EPB_FlagsOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EPB_HashOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EPB_DropCountOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EPB_PacketIDOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EPB_QueueOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EPB_VerdictOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.NS_DNSNameOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.NS_DNSIP4AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.NS_DNSIP6AddrOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_StartTimeOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_EndTimeOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_IFRecvOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_IFDropOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_FilterAcceptOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_OSDropOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ISB_UsrDelivOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.PACK_FlagsOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.PACK_HashOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.NameResolutionRecord
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.UnknownRecord
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.EndRecord
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IPv4Record
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.IPv6Record
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.DSBSecrets
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.UnknownSecrets
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.TLSKeyLog
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.WireGuardKeyLog
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ZigBeeNWKKey
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcapng.ZigBeeAPSKey
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html
