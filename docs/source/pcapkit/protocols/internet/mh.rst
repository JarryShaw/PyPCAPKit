MH - Mobility Header
====================

.. module:: pcapkit.protocols.internet.mh

:mod:`pcapkit.protocols.internet.mh` contains
:class:`~pcapkit.protocols.internet.mh.MH` only,
which implements extractor for Mobility Header
(MH) [*]_, whose structure is described as below:

======= ========= ================== ===============================
Octets      Bits        Name                    Description
======= ========= ================== ===============================
  0           0   ``mh.next``                 Next Header
  1           8   ``mh.length``               Header Length
  2          16   ``mh.type``                 Mobility Header Type
  3          24                               Reserved
  4          32   ``mh.chksum``               Checksum
  6          48   ``mh.data``                 Message Data
======= ========= ================== ===============================

.. todo::

   The CGA Parameters option (type 12) is the one registered mobility option
   still on the generic handler. It is unreachable rather than unimplemented --
   see the Mobility Header section of :doc:`/pep` for the two faults involved,
   both of which are in shared field machinery rather than here.

.. autoclass:: pcapkit.protocols.internet.mh.MH
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: register_message
   .. automethod:: register_option
   .. automethod:: register_extension

   .. automethod:: read
   .. automethod:: make

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
   .. automethod:: _read_msg_hi
   .. automethod:: _read_msg_hack
   .. automethod:: _read_msg_brm
   .. automethod:: _read_msg_fbm
   .. automethod:: _read_msg_has
   .. automethod:: _read_msg_hb
   .. automethod:: _read_msg_lra
   .. automethod:: _read_msg_lri
   .. automethod:: _read_msg_sq
   .. automethod:: _read_msg_sr
   .. automethod:: _read_msg_upa
   .. automethod:: _read_msg_upn

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
   .. automethod:: _make_msg_hi
   .. automethod:: _make_msg_hack
   .. automethod:: _make_msg_brm
   .. automethod:: _make_msg_fbm
   .. automethod:: _make_msg_has
   .. automethod:: _make_msg_hb
   .. automethod:: _make_msg_lra
   .. automethod:: _make_msg_lri
   .. automethod:: _make_msg_sq
   .. automethod:: _make_msg_sr
   .. automethod:: _make_msg_upa
   .. automethod:: _make_msg_upn

   .. automethod:: _read_mh_options
   .. automethod:: _read_fid_suboptions
   .. automethod:: _read_ani_suboptions
   .. automethod:: _read_qos_attributes
   .. automethod:: _read_lcmp_suboptions
   .. automethod:: _decode_signed
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
   .. automethod:: _read_opt_exp
   .. automethod:: _read_opt_badf
   .. automethod:: _read_opt_ipv6_ap
   .. automethod:: _read_opt_alt_ipv4_coa
   .. automethod:: _read_opt_ams4
   .. automethod:: _read_opt_ams6
   .. automethod:: _read_opt_anchored
   .. automethod:: _read_opt_ani
   .. automethod:: _read_opt_att
   .. automethod:: _read_opt_bid
   .. automethod:: _read_opt_cr
   .. automethod:: _read_opt_dlif_lla
   .. automethod:: _read_opt_dlif_lladdr
   .. automethod:: _read_opt_dmnp
   .. automethod:: _read_opt_dns
   .. automethod:: _read_opt_fid
   .. automethod:: _read_opt_fs
   .. automethod:: _read_opt_gre
   .. automethod:: _read_opt_hi
   .. automethod:: _read_opt_hnp
   .. automethod:: _read_opt_ipv4_ack
   .. automethod:: _read_opt_ipv4_coa
   .. automethod:: _read_opt_ipv4_dhcp
   .. automethod:: _read_opt_ipv4_hoa
   .. automethod:: _read_opt_ipv4_hoa_rep
   .. automethod:: _read_opt_ipv4_hoa_req
   .. automethod:: _read_opt_ipv4_router
   .. automethod:: _read_opt_lcmp
   .. automethod:: _read_opt_lla_addr
   .. automethod:: _read_opt_lma_up
   .. automethod:: _read_opt_lmaa
   .. automethod:: _read_opt_load
   .. automethod:: _read_opt_local_prefix
   .. automethod:: _read_opt_mag_addr
   .. automethod:: _read_opt_mag_id
   .. automethod:: _read_opt_mag_mp
   .. automethod:: _read_opt_mcast
   .. automethod:: _read_opt_mcast_ack
   .. automethod:: _read_opt_mcast_sel
   .. automethod:: _read_opt_mn_group
   .. automethod:: _read_opt_mn_lla_iid
   .. automethod:: _read_opt_mn_lli
   .. automethod:: _read_opt_nat
   .. automethod:: _read_opt_offload
   .. automethod:: _read_opt_prev_maar
   .. automethod:: _read_opt_qos
   .. automethod:: _read_opt_rc
   .. automethod:: _read_opt_redirect
   .. automethod:: _read_opt_restart
   .. automethod:: _read_opt_serv_maar
   .. automethod:: _read_opt_service
   .. automethod:: _read_opt_timestamp
   .. automethod:: _read_opt_transient
   .. automethod:: _read_opt_vendor

   .. automethod:: _make_mh_options
   .. automethod:: _make_fid_suboptions
   .. automethod:: _make_fid_suboption
   .. automethod:: _make_ani_suboptions
   .. automethod:: _make_ani_suboption
   .. automethod:: _make_qos_attributes
   .. automethod:: _make_qos_attribute
   .. automethod:: _make_lcmp_suboptions
   .. automethod:: _make_lcmp_suboption
   .. automethod:: _seconds
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
   .. automethod:: _make_opt_exp
   .. automethod:: _make_opt_badf
   .. automethod:: _make_opt_ipv6_ap
   .. automethod:: _make_opt_alt_ipv4_coa
   .. automethod:: _make_opt_ams4
   .. automethod:: _make_opt_ams6
   .. automethod:: _make_opt_anchored
   .. automethod:: _make_opt_ani
   .. automethod:: _make_opt_att
   .. automethod:: _make_opt_bid
   .. automethod:: _make_opt_cr
   .. automethod:: _make_opt_dlif_lla
   .. automethod:: _make_opt_dlif_lladdr
   .. automethod:: _make_opt_dmnp
   .. automethod:: _make_opt_dns
   .. automethod:: _make_opt_fid
   .. automethod:: _make_opt_fs
   .. automethod:: _make_opt_gre
   .. automethod:: _make_opt_hi
   .. automethod:: _make_opt_hnp
   .. automethod:: _make_opt_ipv4_ack
   .. automethod:: _make_opt_ipv4_coa
   .. automethod:: _make_opt_ipv4_dhcp
   .. automethod:: _make_opt_ipv4_hoa
   .. automethod:: _make_opt_ipv4_hoa_rep
   .. automethod:: _make_opt_ipv4_hoa_req
   .. automethod:: _make_opt_ipv4_router
   .. automethod:: _make_opt_lcmp
   .. automethod:: _make_opt_lla_addr
   .. automethod:: _make_opt_lma_up
   .. automethod:: _make_opt_lmaa
   .. automethod:: _make_opt_load
   .. automethod:: _make_opt_local_prefix
   .. automethod:: _make_opt_mag_addr
   .. automethod:: _make_opt_mag_id
   .. automethod:: _make_opt_mag_mp
   .. automethod:: _make_opt_mcast
   .. automethod:: _make_opt_mcast_ack
   .. automethod:: _make_opt_mcast_sel
   .. automethod:: _make_opt_mn_group
   .. automethod:: _make_opt_mn_lla_iid
   .. automethod:: _make_opt_mn_lli
   .. automethod:: _make_opt_nat
   .. automethod:: _make_opt_offload
   .. automethod:: _make_opt_prev_maar
   .. automethod:: _make_opt_qos
   .. automethod:: _make_opt_rc
   .. automethod:: _make_opt_redirect
   .. automethod:: _make_opt_restart
   .. automethod:: _make_opt_serv_maar
   .. automethod:: _make_opt_service
   .. automethod:: _make_opt_timestamp
   .. automethod:: _make_opt_transient
   .. automethod:: _make_opt_vendor

   .. automethod:: _read_cga_extensions
   .. automethod:: _read_ext_none
   .. automethod:: _read_ext_multiprefix
   .. automethod:: _read_ext_exp

   .. automethod:: _make_cga_extensions
   .. automethod:: _make_ext_none
   .. automethod:: _make_ext_multiprefix
   .. automethod:: _make_ext_exp

   .. autoattribute:: __message__
      :no-value:
   .. autoattribute:: __option__
      :no-value:
   .. autoattribute:: __extension__
      :no-value:

   .. automethod:: __post_init__
   .. automethod:: __index__

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.internet.mh.NTPTimestamp
   :members:
   :show-inheritance:

   .. attribute:: seconds
      :type: int

      Seconds since 1 January 1900.

   .. attribute:: fraction
      :type: int

      Fraction of a second.

.. autoclass:: pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.IPv6AddressPrefixCode
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.PMIPv6Timestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.LocalizedRoutingStatus
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.mh.LMAAddressCode
   :members:
   :undoc-members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.mh

.. autoclass:: pcapkit.protocols.schema.internet.mh.MH
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingRefreshAdviceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AlternateCareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.NonceIndicesOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AuthorizationDataOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MobileNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MNIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AuthOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MesgIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CGAParametersRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CGAExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CGAParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CGAParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnknownExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MultiPrefixExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.Packet
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.SignatureOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.PermanentHomeKeygenTokenOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CareofTestInitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CareofTestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ExperimentalMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BADFOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv6AddressPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnknownMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingRefreshRequestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HomeTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CareofTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HomeTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.CareofTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingErrorMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FastBindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FastBindingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FastNeighborAdvertisementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ExperimentalMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HandoverInitiateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HandoverAcknowledgeMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HeartbeatMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HomeAgentSwitchMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingRevocationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LocalizedRoutingInitiationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LocalizedRoutingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UpdateNotificationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UpdateNotificationAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FlowBindingMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.SubscriptionQueryMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.SubscriptionResponseMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HomeNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HandoffIndicatorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AccessTechnologyTypeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MNLLIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.TimestampOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.RestartCounterOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DNSUpdateOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.VendorSpecificOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ServiceSelectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4AddressAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.NATDetectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.GREKeyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4HomeAddressRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4HomeAddressReplyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4DefaultRouterAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4DHCPSupportModeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ContextRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LMAAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MNLLAIIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.TransientBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FlowSummaryOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FlowIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.RedirectCapabilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.RedirectOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LoadInformationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AlternateIPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MNGroupIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MAGIPv6AddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AccessNetworkIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4TrafficOffloadSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DynamicIPMulticastSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DelegatedMNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ActiveMulticastSubscriptionIPv4Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ActiveMulticastSubscriptionIPv6Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.QualityOfServiceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LMAUserPlaneAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MulticastMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MulticastAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LMAControlledMAGParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MAGMultipathBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MAGIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AnchoredPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LocalPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.PreviousMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ServingMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DLIFLinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DLIFLinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnassignedFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.PadFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BIDReferenceSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.TrafficSelectorSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FlowBindingActionSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.TargetCareofAddressSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnassignedANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANINetworkIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANIGeoLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANIOperatorIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANICivicLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANIMAGGroupIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANIUpdateTimerSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.QoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnassignedQoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.PerSessionBitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AllocationRetentionPriorityAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.QoSTrafficSelectorAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.QoSVendorSpecificAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UnassignedLMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingReregistrationControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HeartbeatControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ExperimentalExtension
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANSIKeyLengthTest
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MultiPrefixExtensionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingUpdateMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingAcknowledgementMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FastBindingUpdateMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FastBindingAcknowledgmentMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HandoverInitiateMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HandoverAcknowledgeMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.HeartbeatMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FixedPointTimestamp
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingRevocationMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.LocalizedRoutingAcknowledgmentMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.FlowBindingMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.UpdateNotificationMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.SubscriptionResponseMessageFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DNSUpdateOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4HomeAddressOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.PrefixLengthOnly
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.NATDetectionOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.IPv4DHCPSupportModeOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.RedirectOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.BindingIdentifierOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.TransientBindingOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ModeFlagOnly
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.DelegatedMNPOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.MAGMultipathBindingOptionFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.ANINetworkIdentifierFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.GeoLocationDegrees
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.SessionBitRateFlags
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.mh.AllocationRetentionPriorityFields
   :members:
   :undoc-members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.internet.mh.mh_data_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.mn_id_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.pad_opt_data_len
.. autofunction:: pcapkit.protocols.schema.internet.mh.bid_address_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.br_code_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.dmnp_prefix_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.fb_code_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.lma_address_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.lma_user_plane_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.pad_subopt_data_len
.. autofunction:: pcapkit.protocols.schema.internet.mh.target_coa_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.mh

.. autoclass:: pcapkit.protocols.data.internet.mh.MH
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingRefreshAdviceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AlternateCareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.NonceIndicesOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AuthorizationDataOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MobileNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MNIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AuthOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MesgIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CGAParametersRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CGAExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CGAParameter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CGAParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnknownExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MultiPrefixExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.SignatureOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.PermanentHomeKeygenTokenOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CareofTestInitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CareofTestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ExperimentalMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BADFOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv6AddressPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnknownMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingRefreshRequestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HomeTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CareofTestInitMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HomeTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.CareofTestMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingErrorMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FastBindingUpdateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FastBindingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FastNeighborAdvertisementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ExperimentalMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HandoverInitiateMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HandoverAcknowledgeMessage
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6

.. autoclass:: pcapkit.protocols.data.internet.mh.HeartbeatMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HomeAgentSwitchMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingRevocationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LocalizedRoutingInitiationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LocalizedRoutingAcknowledgmentMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UpdateNotificationMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UpdateNotificationAcknowledgementMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FlowBindingMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.SubscriptionQueryMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.SubscriptionResponseMessage
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HomeNetworkPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HandoffIndicatorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AccessTechnologyTypeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MNLLIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.TimestampOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.RestartCounterOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.DNSUpdateOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.VendorSpecificOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ServiceSelectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4AddressAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.NATDetectionOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.GREKeyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4HomeAddressRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4HomeAddressReplyOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4DefaultRouterAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4DHCPSupportModeOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ContextRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LMAAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MNLLAIIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.TransientBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FlowSummaryOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FlowIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.RedirectCapabilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.RedirectOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LoadInformationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AlternateIPv4CareofAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MNGroupIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MAGIPv6AddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AccessNetworkIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.IPv4TrafficOffloadSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.DynamicIPMulticastSelectorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.DelegatedMNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ActiveMulticastSubscriptionIPv4Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ActiveMulticastSubscriptionIPv6Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.QualityOfServiceOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LMAUserPlaneAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MulticastMobilityOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MulticastAcknowledgementOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LMAControlledMAGParametersOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MAGMultipathBindingOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.MAGIdentifierOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AnchoredPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LocalPrefixOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.PreviousMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ServingMAAROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.DLIFLinkLocalAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.DLIFLinkLayerAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ContextRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnassignedFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.PadFlowIdentificationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BIDReferenceSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.TrafficSelectorSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.FlowBindingActionSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.TargetCareofAddressSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnassignedANISuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANINetworkIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANIGeoLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANIOperatorIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANICivicLocationSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANIMAGGroupIdentifierSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ANIUpdateTimerSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.QoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnassignedQoSAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.PerSessionBitRateAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.AllocationRetentionPriorityAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.QoSTrafficSelectorAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.QoSVendorSpecificAttribute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.LMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.UnassignedLMAControlledMAGSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.BindingReregistrationControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.HeartbeatControlSuboption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.mh.ExperimentalExtension
   :members:
   :show-inheritance:
