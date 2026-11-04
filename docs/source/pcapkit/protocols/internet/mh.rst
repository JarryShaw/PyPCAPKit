MH - Mobility Header
====================

.. module:: pcapkit.protocols.internet.mh
.. module:: pcapkit.protocols.internet.mh.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus``,
   ``pcapkit.protocols.internet.mh.IPv6AddressPrefixCode``,
   ``pcapkit.protocols.internet.mh.LocalizedRoutingStatus`` and
   ``pcapkit.protocols.internet.mh.LMAAddressCode``, with no alias: they are in this
   module, and :mod:`pcapkit.protocols.internet.mh` exports the protocol class alone
   (:issue:`2534`).

:mod:`pcapkit.protocols.internet.mh.protocol` contains
:class:`~pcapkit.protocols.internet.mh.protocol.MH`,
which implements the extractor for Mobility Header
(MH) [*]_, whose structure is described as below:

======= ========= ================== ===============================
Octets      Bits        Name                    Description
======= ========= ================== ===============================
  0           0   ``mh.next``                 Next Header
  1           8   ``mh.length``               Header Length
  2          16   ``mh.type``                 Mobility Header Type
  3          24   ``mh.reserved``             Reserved
  4          32   ``mh.chksum``               Checksum
  6          48   ``mh.data``                 Message Data
======= ========= ================== ===============================

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.internet.mh.NTPTimestamp``, with no alias; use
   :class:`pcapkit.protocols.internet.mh.data.NTPTimestamp` instead
   (:issue:`1886`).

.. autoclass:: pcapkit.protocols.internet.mh.protocol.MH
   :no-members:
   :show-inheritance:

   .. autoattribute:: __message__
      :no-value:

   .. autoattribute:: __option__
      :no-value:

   .. autoattribute:: __extension__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_message
   .. automethod:: register_option
   .. automethod:: register_extension
   .. automethod:: id

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_msg_unknown
   .. automethod:: _read_msg_brr
   .. automethod:: _read_msg_hoti
   .. automethod:: _read_msg_coti
   .. automethod:: _read_msg_hot
   .. automethod:: _read_msg_cot
   .. automethod:: _read_msg_bu
   .. automethod:: _read_msg_ba
   .. automethod:: _read_msg_be
   .. automethod:: _read_msg_fbu
   .. automethod:: _read_msg_fback
   .. automethod:: _read_msg_fna
   .. automethod:: _read_msg_emh
   .. automethod:: _read_msg_has
   .. automethod:: _read_msg_hb
   .. automethod:: _read_msg_hi
   .. automethod:: _read_msg_hack
   .. automethod:: _read_msg_brm
   .. automethod:: _read_msg_lri
   .. automethod:: _read_msg_lra
   .. automethod:: _read_msg_upn
   .. automethod:: _read_msg_upa
   .. automethod:: _read_msg_fbm
   .. automethod:: _read_msg_sq
   .. automethod:: _read_msg_sr
   .. automethod:: _read_opt_none
   .. automethod:: _read_opt_pad
   .. automethod:: _read_opt_bra
   .. automethod:: _read_opt_aca
   .. automethod:: _read_opt_ni
   .. automethod:: _read_opt_bad
   .. automethod:: _read_opt_mnp
   .. automethod:: _read_opt_lla
   .. automethod:: _read_opt_mn_id
   .. automethod:: _read_opt_auth
   .. automethod:: _read_opt_mesg_id
   .. automethod:: _read_opt_cga_pr
   .. automethod:: _read_opt_cga_param
   .. automethod:: _read_opt_signature
   .. automethod:: _read_opt_phkt
   .. automethod:: _read_opt_ct_init
   .. automethod:: _read_opt_ct
   .. automethod:: _read_opt_dns
   .. automethod:: _read_opt_exp
   .. automethod:: _read_opt_vendor
   .. automethod:: _read_opt_service
   .. automethod:: _read_opt_badf
   .. automethod:: _read_opt_hnp
   .. automethod:: _read_opt_hi
   .. automethod:: _read_opt_att
   .. automethod:: _read_opt_mn_lli
   .. automethod:: _read_opt_lla_addr
   .. automethod:: _read_opt_timestamp
   .. automethod:: _read_opt_restart
   .. automethod:: _read_opt_ipv4_hoa
   .. automethod:: _read_opt_ipv4_ack
   .. automethod:: _read_opt_nat
   .. automethod:: _read_opt_ipv4_coa
   .. automethod:: _read_opt_gre
   .. automethod:: _read_opt_ipv6_ap
   .. automethod:: _read_opt_bid
   .. automethod:: _read_opt_ipv4_hoa_req
   .. automethod:: _read_opt_ipv4_hoa_rep
   .. automethod:: _read_opt_ipv4_router
   .. automethod:: _read_opt_ipv4_dhcp
   .. automethod:: _read_opt_cr
   .. automethod:: _read_opt_lmaa
   .. automethod:: _read_opt_mn_lla_iid
   .. automethod:: _read_opt_transient
   .. automethod:: _read_opt_fs
   .. automethod:: _read_opt_fid
   .. automethod:: _read_opt_rc
   .. automethod:: _read_opt_redirect
   .. automethod:: _read_opt_load
   .. automethod:: _read_opt_alt_ipv4_coa
   .. automethod:: _read_opt_mn_group
   .. automethod:: _read_opt_mag_addr
   .. automethod:: _read_opt_ani
   .. automethod:: _read_opt_offload
   .. automethod:: _read_opt_mcast_sel
   .. automethod:: _read_opt_dmnp
   .. automethod:: _read_opt_ams4
   .. automethod:: _read_opt_ams6
   .. automethod:: _read_opt_qos
   .. automethod:: _read_opt_lma_up
   .. automethod:: _read_opt_mcast
   .. automethod:: _read_opt_mcast_ack
   .. automethod:: _read_opt_lcmp
   .. automethod:: _read_opt_mag_mp
   .. automethod:: _read_opt_mag_id
   .. automethod:: _read_opt_anchored
   .. automethod:: _read_opt_local_prefix
   .. automethod:: _read_opt_prev_maar
   .. automethod:: _read_opt_serv_maar
   .. automethod:: _read_opt_dlif_lla
   .. automethod:: _read_opt_dlif_lladdr
   .. automethod:: _read_ext_none
   .. automethod:: _read_ext_multiprefix
   .. automethod:: _read_ext_exp
   .. automethod:: _make_msg_unknown
   .. automethod:: _make_msg_brr
   .. automethod:: _make_msg_hoti
   .. automethod:: _make_msg_coti
   .. automethod:: _make_msg_hot
   .. automethod:: _make_msg_cot
   .. automethod:: _make_msg_bu
   .. automethod:: _make_msg_ba
   .. automethod:: _make_msg_be
   .. automethod:: _make_msg_fbu
   .. automethod:: _make_msg_fback
   .. automethod:: _make_msg_fna
   .. automethod:: _make_msg_emh
   .. automethod:: _make_msg_has
   .. automethod:: _make_msg_hb
   .. automethod:: _make_msg_hi
   .. automethod:: _make_msg_hack
   .. automethod:: _make_msg_brm
   .. automethod:: _make_msg_lri
   .. automethod:: _make_msg_lra
   .. automethod:: _make_msg_upn
   .. automethod:: _make_msg_upa
   .. automethod:: _make_msg_fbm
   .. automethod:: _make_msg_sq
   .. automethod:: _make_msg_sr
   .. automethod:: _make_opt_none
   .. automethod:: _make_opt_pad
   .. automethod:: _make_opt_bra
   .. automethod:: _make_opt_aca
   .. automethod:: _make_opt_ni
   .. automethod:: _make_opt_bad
   .. automethod:: _make_opt_mnp
   .. automethod:: _make_opt_lla
   .. automethod:: _make_opt_mn_id
   .. automethod:: _make_opt_auth
   .. automethod:: _make_opt_mesg_id
   .. automethod:: _make_opt_cga_pr
   .. automethod:: _make_opt_cga_param
   .. automethod:: _make_opt_signature
   .. automethod:: _make_opt_phkt
   .. automethod:: _make_opt_ct_init
   .. automethod:: _make_opt_ct
   .. automethod:: _make_opt_dns
   .. automethod:: _make_opt_exp
   .. automethod:: _make_opt_vendor
   .. automethod:: _make_opt_service
   .. automethod:: _make_opt_badf
   .. automethod:: _make_opt_hnp
   .. automethod:: _make_opt_hi
   .. automethod:: _make_opt_att
   .. automethod:: _make_opt_mn_lli
   .. automethod:: _make_opt_lla_addr
   .. automethod:: _make_opt_timestamp
   .. automethod:: _make_opt_restart
   .. automethod:: _make_opt_ipv4_hoa
   .. automethod:: _make_opt_ipv4_ack
   .. automethod:: _make_opt_nat
   .. automethod:: _make_opt_ipv4_coa
   .. automethod:: _make_opt_gre
   .. automethod:: _make_opt_ipv6_ap
   .. automethod:: _make_opt_bid
   .. automethod:: _make_opt_ipv4_hoa_req
   .. automethod:: _make_opt_ipv4_hoa_rep
   .. automethod:: _make_opt_ipv4_router
   .. automethod:: _make_opt_ipv4_dhcp
   .. automethod:: _make_opt_cr
   .. automethod:: _make_opt_lmaa
   .. automethod:: _make_opt_mn_lla_iid
   .. automethod:: _make_opt_transient
   .. automethod:: _make_opt_fs
   .. automethod:: _make_opt_fid
   .. automethod:: _make_opt_rc
   .. automethod:: _make_opt_redirect
   .. automethod:: _make_opt_load
   .. automethod:: _make_opt_alt_ipv4_coa
   .. automethod:: _make_opt_mn_group
   .. automethod:: _make_opt_mag_addr
   .. automethod:: _make_opt_ani
   .. automethod:: _make_opt_offload
   .. automethod:: _make_opt_mcast_sel
   .. automethod:: _make_opt_dmnp
   .. automethod:: _make_opt_ams4
   .. automethod:: _make_opt_ams6
   .. automethod:: _make_opt_qos
   .. automethod:: _make_opt_lma_up
   .. automethod:: _make_opt_mcast
   .. automethod:: _make_opt_mcast_ack
   .. automethod:: _make_opt_lcmp
   .. automethod:: _make_opt_mag_mp
   .. automethod:: _make_opt_mag_id
   .. automethod:: _make_opt_anchored
   .. automethod:: _make_opt_local_prefix
   .. automethod:: _make_opt_prev_maar
   .. automethod:: _make_opt_serv_maar
   .. automethod:: _make_opt_dlif_lla
   .. automethod:: _make_opt_dlif_lladdr
   .. automethod:: _make_ext_none
   .. automethod:: _make_ext_multiprefix
   .. automethod:: _make_ext_exp
   .. automethod:: _read_mh_options
   .. automethod:: _read_fid_suboptions
   .. automethod:: _read_ani_suboptions
   .. automethod:: _read_qos_attributes
   .. automethod:: _read_lcmp_suboptions
   .. automethod:: _read_cga_extensions
   .. automethod:: _make_mh_options
   .. automethod:: _make_fid_suboptions
   .. automethod:: _make_fid_suboption
   .. automethod:: _make_ani_suboptions
   .. automethod:: _make_ani_suboption
   .. automethod:: _make_qos_attributes
   .. automethod:: _make_qos_attribute
   .. automethod:: _make_lcmp_suboptions
   .. automethod:: _seconds
   .. automethod:: _make_lcmp_suboption
   .. automethod:: _make_cga_extensions

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.internet.mh.protocol.FastBindingAcknowledgmentStatus
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.protocol.IPv6AddressPrefixCode
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.protocol.LocalizedRoutingStatus
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.protocol.LMAAddressCode
   :members:
   :undoc-members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.mh.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.mh``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.mh.schema.MH
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingRefreshAdviceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AlternateCareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.NonceIndicesOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AuthorizationDataOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MobileNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MNIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AuthOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MesgIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CGAParametersRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CGAExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CGAParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CGAParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnknownExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MultiPrefixExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.Packet
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.SignatureOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.PermanentHomeKeygenTokenOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CareofTestInitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CareofTestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ExperimentalMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BADFOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv6AddressPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnknownMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingRefreshRequestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HomeTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CareofTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HomeTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.CareofTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingErrorMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FastBindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FastBindingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FastNeighborAdvertisementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ExperimentalMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HandoverInitiateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HandoverAcknowledgeMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HeartbeatMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HomeAgentSwitchMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingRevocationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LocalizedRoutingInitiationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LocalizedRoutingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UpdateNotificationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UpdateNotificationAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FlowBindingMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.SubscriptionQueryMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.SubscriptionResponseMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HomeNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HandoffIndicatorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AccessTechnologyTypeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MNLLIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.TimestampOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.RestartCounterOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DNSUpdateOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.VendorSpecificOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ServiceSelectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4AddressAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.NATDetectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.GREKeyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4HomeAddressRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4HomeAddressReplyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4DefaultRouterAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4DHCPSupportModeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ContextRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LMAAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MNLLAIIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.TransientBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FlowSummaryOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FlowIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.RedirectCapabilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.RedirectOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LoadInformationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AlternateIPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MNGroupIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MAGIPv6AddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AccessNetworkIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4TrafficOffloadSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DynamicIPMulticastSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DelegatedMNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ActiveMulticastSubscriptionIPv4Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ActiveMulticastSubscriptionIPv6Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.QualityOfServiceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LMAUserPlaneAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MulticastMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MulticastAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LMAControlledMAGParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MAGMultipathBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MAGIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AnchoredPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LocalPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.PreviousMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ServingMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DLIFLinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DLIFLinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnassignedFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.PadFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BIDReferenceSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.TrafficSelectorSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FlowBindingActionSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.TargetCareofAddressSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnassignedANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANINetworkIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANIGeoLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANIOperatorIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANICivicLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANIMAGGroupIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANIUpdateTimerSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.QoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnassignedQoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.PerSessionBitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AllocationRetentionPriorityAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.QoSTrafficSelectorAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.QoSVendorSpecificAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UnassignedLMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingReregistrationControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HeartbeatControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ExperimentalExtension
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANSIKeyLengthTest
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MultiPrefixExtensionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingUpdateMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingAcknowledgementMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FastBindingUpdateMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FastBindingAcknowledgmentMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HandoverInitiateMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HandoverAcknowledgeMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.HeartbeatMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FixedPointTimestamp
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingRevocationMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.LocalizedRoutingAcknowledgmentMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.FlowBindingMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.UpdateNotificationMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.SubscriptionResponseMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DNSUpdateOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4HomeAddressOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.PrefixLengthOnly
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.NATDetectionOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.IPv4DHCPSupportModeOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.RedirectOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.BindingIdentifierOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.TransientBindingOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ModeFlagOnly
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.DelegatedMNPOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.MAGMultipathBindingOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.ANINetworkIdentifierFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.GeoLocationDegrees
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.SessionBitRateFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.schema.AllocationRetentionPriorityFields
   :members:
   :undoc-members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.mh.schema.mh_data_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.mn_id_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.pad_opt_data_len
.. autofunction:: pcapkit.protocols.internet.mh.schema.bid_address_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.br_code_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.cga_public_key_length
.. autofunction:: pcapkit.protocols.internet.mh.schema.item_list_length
.. autofunction:: pcapkit.protocols.internet.mh.schema.dmnp_prefix_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.fb_code_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.lma_address_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.lma_user_plane_selector
.. autofunction:: pcapkit.protocols.internet.mh.schema.pad_subopt_data_len
.. autofunction:: pcapkit.protocols.internet.mh.schema.target_coa_selector

Data Models
-----------

.. module:: pcapkit.protocols.internet.mh.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.mh``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.mh.data.MH
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingRefreshAdviceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AlternateCareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.NonceIndicesOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AuthorizationDataOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MobileNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MNIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AuthOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MesgIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.NTPTimestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CGAParametersRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CGAExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CGAParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CGAParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnknownExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MultiPrefixExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.SignatureOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.PermanentHomeKeygenTokenOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CareofTestInitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CareofTestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ExperimentalMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BADFOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv6AddressPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnknownMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingRefreshRequestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HomeTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CareofTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HomeTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.CareofTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingErrorMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FastBindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FastBindingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FastNeighborAdvertisementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ExperimentalMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HandoverInitiateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HandoverAcknowledgeMessage
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6

.. autoclass:: pcapkit.protocols.internet.mh.data.HeartbeatMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HomeAgentSwitchMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingRevocationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LocalizedRoutingInitiationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LocalizedRoutingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UpdateNotificationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UpdateNotificationAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FlowBindingMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.SubscriptionQueryMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.SubscriptionResponseMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HomeNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HandoffIndicatorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AccessTechnologyTypeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MNLLIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.TimestampOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.PMIPv6Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.RestartCounterOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.DNSUpdateOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.VendorSpecificOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ServiceSelectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4AddressAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.NATDetectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.GREKeyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4HomeAddressRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4HomeAddressReplyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4DefaultRouterAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4DHCPSupportModeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ContextRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LMAAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MNLLAIIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.TransientBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FlowSummaryOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FlowIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.RedirectCapabilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.RedirectOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LoadInformationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AlternateIPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MNGroupIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MAGIPv6AddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AccessNetworkIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.IPv4TrafficOffloadSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.DynamicIPMulticastSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.DelegatedMNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ActiveMulticastSubscriptionIPv4Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ActiveMulticastSubscriptionIPv6Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.QualityOfServiceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LMAUserPlaneAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MulticastMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MulticastAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LMAControlledMAGParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MAGMultipathBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.MAGIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AnchoredPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LocalPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.PreviousMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ServingMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.DLIFLinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.DLIFLinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ContextRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnassignedFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.PadFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BIDReferenceSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.TrafficSelectorSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.FlowBindingActionSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.TargetCareofAddressSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnassignedANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANINetworkIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANIGeoLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANIOperatorIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANICivicLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANIMAGGroupIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ANIUpdateTimerSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.QoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnassignedQoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.PerSessionBitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.AllocationRetentionPriorityAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.QoSTrafficSelectorAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.QoSVendorSpecificAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.LMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.UnassignedLMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.BindingReregistrationControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.HeartbeatControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.data.ExperimentalExtension
   :members:
   :show-inheritance:
