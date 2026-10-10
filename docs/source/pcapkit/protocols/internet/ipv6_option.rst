IPv6 Options - Shared Option Helpers
====================================

.. module:: pcapkit.protocols.schema.internet.ipv6_option

:mod:`pcapkit.protocols.schema.internet.ipv6_option` contains the field helpers
shared by the option schemas of
:mod:`~pcapkit.protocols.schema.internet.hopopt` (HOPOPT) and
:mod:`~pcapkit.protocols.schema.internet.ipv6_opts` (IPv6-Opts), since both
headers carry the same IPv6 options [*]_. A helper that reports an error takes
the header's name as ``prefix``, and a selector takes the header's option
schemas. Each header module binds them in a function of the same name, which
is what its fields use.

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.rpl_opt_sub_tlv_len
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.mpl_opt_seed_id_len
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.pad_opt_data_len
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.calipso_pad_len
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.mpl_opt_pad_len

.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.smf_dpd_data_selector
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.smf_i_dpd_tid_selector
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.smf_i_dpd_id_len
.. autofunction:: pcapkit.protocols.schema.internet.ipv6_option.quick_start_data_selector

.. rubric:: Footnotes

.. [*] https://www.rfc-editor.org/rfc/rfc8200#section-4.2
