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

   Implements extractor for message data of all MH types.

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

   .. automethod:: _make_msg_unknown
   .. automethod:: _make_msg_brr
   .. automethod:: _make_msg_hoti
   .. automethod:: _make_msg_coti
   .. automethod:: _make_msg_hot
   .. automethod:: _make_msg_cot
   .. automethod:: _make_msg_bu
   .. automethod:: _make_msg_ba
   .. automethod:: _make_msg_be

   .. automethod:: _read_mh_options
   .. automethod:: _read_opt_none
   .. automethod:: _read_opt_pad
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

   .. automethod:: _make_mh_options
   .. automethod:: _make_opt_none
   .. automethod:: _make_opt_pad
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

   .. automethod:: _read_cga_extensions
   .. automethod:: _read_ext_none
   .. automethod:: _read_ext_multiprefix

   .. automethod:: _make_cga_extensions
   .. automethod:: _make_ext_none
   .. automethod:: _make_ext_multiprefix

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

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.internet.mh.mh_data_selector
.. autofunction:: pcapkit.protocols.schema.internet.mh.mn_id_selector

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

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6
