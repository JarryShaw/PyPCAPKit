IPv6-Opts - Destination Options for IPv6
========================================

.. module:: pcapkit.protocols.internet.ipv6_opts
.. module:: pcapkit.protocols.internet.ipv6_opts.protocol

:mod:`pcapkit.protocols.internet.ipv6_opts.protocol` contains
:class:`~pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts`
only, which implements the extractor for Destination Options
for IPv6 (IPv6-Opts) [*]_, whose structure is described
as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``opts.next``             Next Header
  1           8   ``opts.length``           Header Extension Length
  2          16   ``opts.options``          Options
======= ========= =================== =================================

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts
   :no-members:
   :show-inheritance:

   .. autoattribute:: __option__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_option
   .. automethod:: id

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_ipv6_opts
   .. automethod:: _make_ipv6_opts
   .. automethod:: _read_opt_none
   .. automethod:: _read_opt_pad
   .. automethod:: _read_opt_tun
   .. automethod:: _read_opt_ra
   .. automethod:: _read_opt_calipso
   .. automethod:: _read_opt_smf_dpd
   .. automethod:: _read_opt_pdm
   .. automethod:: _read_opt_rpl
   .. automethod:: _read_opt_qs
   .. automethod:: _read_opt_mpl
   .. automethod:: _read_opt_ilnp
   .. automethod:: _read_opt_lio
   .. automethod:: _read_opt_jumbo
   .. automethod:: _read_opt_home
   .. automethod:: _read_opt_ip_dff
   .. automethod:: _make_opt_none
   .. automethod:: _make_opt_pad
   .. automethod:: _make_opt_tun
   .. automethod:: _make_opt_ra
   .. automethod:: _make_opt_calipso
   .. automethod:: _make_opt_smf_dpd
   .. automethod:: _make_opt_pdm
   .. automethod:: _make_opt_rpl
   .. automethod:: _make_opt_qs
   .. automethod:: _make_opt_mpl
   .. automethod:: _make_opt_ilnp
   .. automethod:: _make_opt_lio
   .. automethod:: _make_opt_jumbo
   .. automethod:: _make_opt_home
   .. automethod:: _make_opt_ip_dff

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipv6_opts.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6_opts``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.IPv6_Opts
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.TunnelEncapsulationLimitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.RouterAlertOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.CALIPSOOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema._SMFDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.SMFDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.SMFIdentificationBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.SMFHashBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.PDMOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema._QuickStartOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.QuickStartOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.QuickStartRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.QuickStartReportOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.RPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.MPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.ILNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.LineIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.JumboPayloadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.IPDFFOption
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.TaggerIDInfo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.QuickStartFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.RPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.MPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.DFFFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.SMFDPDTestFlag
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.QSTestFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.schema.QSNonce
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

The option helpers are shared with
:mod:`~pcapkit.protocols.internet.hopopt.schema` and documented in
:mod:`pcapkit.protocols.internet.ipv6_ext.schema`. The functions below bind
them to this module's error prefix and option schemas;
:func:`~pcapkit.protocols.internet.ipv6_ext.schema.rpl_opt_sub_tlv_len` and
:func:`~pcapkit.protocols.internet.ipv6_ext.schema.pad_opt_data_len` are
used unchanged.

.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.mpl_opt_seed_id_len
.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.calipso_pad_len
.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.mpl_opt_pad_len

.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.smf_dpd_data_selector
.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.smf_i_dpd_tid_selector
.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.smf_i_dpd_id_len
.. autofunction:: pcapkit.protocols.internet.ipv6_opts.schema.quick_start_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipv6_opts.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipv6_opts``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.IPv6_Opts
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.PadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.TunnelEncapsulationLimitOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.RouterAlertOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.CALIPSOOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.SMFDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.SMFIdentificationBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.SMFHashBasedDPDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.PDMOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.QuickStartOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.QuickStartRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.QuickStartReportOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.RPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.RPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.MPLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.MPLFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.ILNPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.LineIdentificationOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.JumboPayloadOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.HomeAddressOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.IPDFFOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.data.DFFFlags
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options
