HOPOPT - IPv6 Hop-by-Hop Options
================================

.. module:: pcapkit.protocols.internet.hopopt
.. module:: pcapkit.protocols.internet.hopopt.protocol

:mod:`pcapkit.protocols.internet.hopopt.protocol` contains
:class:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT`
only, which implements the extractor for IPv6 Hop-by-Hop
Options header (HOPOPT) [*]_, whose structure is
described as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``hopopt.next``             Next Header
  1           8   ``hopopt.length``           Header Extension Length
  2          16   ``hopopt.options``          Options
======= ========= =================== =================================

.. autoclass:: pcapkit.protocols.internet.hopopt.protocol.HOPOPT
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: id

   .. automethod:: register_option

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _read_hopopt_options
   .. automethod:: _read_opt_none
   .. automethod:: _read_opt_pad
   .. automethod:: _read_opt_tun
   .. automethod:: _read_opt_ra
   .. automethod:: _read_opt_calipso
   .. automethod:: _read_opt_smf_dpd
   .. automethod:: _read_opt_pdm
   .. automethod:: _read_opt_qs
   .. automethod:: _read_opt_rpl
   .. automethod:: _read_opt_mpl
   .. automethod:: _read_opt_ilnp
   .. automethod:: _read_opt_lio
   .. automethod:: _read_opt_jumbo
   .. automethod:: _read_opt_home
   .. automethod:: _read_opt_ip_dff

   .. automethod:: _make_hopopt_options
   .. automethod:: _make_opt_none
   .. automethod:: _make_opt_pad
   .. automethod:: _make_opt_tun
   .. automethod:: _make_opt_ra
   .. automethod:: _make_opt_calipso
   .. automethod:: _make_opt_smf_dpd
   .. automethod:: _make_opt_pdm
   .. automethod:: _make_opt_qs
   .. automethod:: _make_opt_rpl
   .. automethod:: _make_opt_mpl
   .. automethod:: _make_opt_ilnp
   .. automethod:: _make_opt_lio
   .. automethod:: _make_opt_jumbo
   .. automethod:: _make_opt_home
   .. automethod:: _make_opt_ip_dff

   .. autoattribute:: __option__
      :no-value:

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.hopopt.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.hopopt``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.HOPOPT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.TunnelEncapsulationLimitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.RouterAlertOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.CALIPSOOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema._SMFDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.SMFDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.SMFIdentificationBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.SMFHashBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.PDMOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema._QuickStartOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.QuickStartOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.QuickStartRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.QuickStartReportOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.RPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.MPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.ILNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.LineIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.JumboPayloadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.IPDFFOption
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.TaggerIDInfo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.QuickStartFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.RPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.MPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.DFFFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.SMFDPDTestFlag
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.QSTestFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.schema.QSNonce
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

The option helpers are shared with
:mod:`~pcapkit.protocols.internet.ipv6_opts.schema` and documented in
:mod:`pcapkit.protocols.internet.ipv6_ext.schema`. The functions below bind
them to this module's error prefix and option schemas;
:func:`~pcapkit.protocols.internet.ipv6_ext.schema.rpl_opt_sub_tlv_len` and
:func:`~pcapkit.protocols.internet.ipv6_ext.schema.pad_opt_data_len` are
used unchanged.

.. autofunction:: pcapkit.protocols.internet.hopopt.schema.mpl_opt_seed_id_len
.. autofunction:: pcapkit.protocols.internet.hopopt.schema.calipso_pad_len
.. autofunction:: pcapkit.protocols.internet.hopopt.schema.mpl_opt_pad_len

.. autofunction:: pcapkit.protocols.internet.hopopt.schema.smf_dpd_data_selector
.. autofunction:: pcapkit.protocols.internet.hopopt.schema.smf_i_dpd_tid_selector
.. autofunction:: pcapkit.protocols.internet.hopopt.schema.smf_i_dpd_id_len
.. autofunction:: pcapkit.protocols.internet.hopopt.schema.quick_start_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.internet.hopopt.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.hopopt``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.hopopt.data.HOPOPT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.TunnelEncapsulationLimitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.RouterAlertOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.CALIPSOOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.SMFDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.SMFIdentificationBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.SMFHashBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.PDMOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.QuickStartOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.QuickStartRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.QuickStartReportOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.RPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.RPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.MPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.MPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.ILNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.LineIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.JumboPayloadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.IPDFFOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.hopopt.data.DFFFlags
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options
