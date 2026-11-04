IPv4 - Internet Protocol Version 4
==================================

.. module:: pcapkit.protocols.internet.ipv4
.. module:: pcapkit.protocols.internet.ipv4.protocol

:mod:`pcapkit.protocols.internet.ipv4.protocol` contains
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` only,
which implements the extractor for Internet Protocol
version 4 (IPv4) [*]_, whose structure is described
as below:

======= ========= ======================= ============================================
Octets      Bits        Name                    Description
======= ========= ======================= ============================================
  0           0   ``ipv4.version``        Version (``4``)
  0           4   ``ipv4.hdr_len``        Internet Header Length (IHL)
  1           8   ``ipv4.tos.pre``        Precedence
  1          11   ``ipv4.tos.del``        Delay
  1          12   ``ipv4.tos.thr``        Throughput
  1          13   ``ipv4.tos.rel``        Reliability
  1          14   ``ipv4.tos.ecn``        Explicit Congestion Notification (ECN)
  2          16   ``ipv4.len``            Total Length
  4          32   ``ipv4.id``             Identification
  6          48   ``ipv4.flags.reserved`` Reserved Bit (must be ``0``)
  6          49   ``ipv4.flags.df``       Don't Fragment (DF)
  6          50   ``ipv4.flags.mf``       More Fragments (MF)
  6          51   ``ipv4.offset``         Fragment Offset
  8          64   ``ipv4.ttl``            Time To Live (TTL)
  9          72   ``ipv4.protocol``       Protocol (Transport Layer)
  10         80   ``ipv4.checksum``       Header Checksum
  12         96   ``ipv4.src``            Source IP Address
  16        128   ``ipv4.dst``            Destination IP Address
  20        160   ``ipv4.options``        IP Options (if IHL > ``5``)
======= ========= ======================= ============================================

.. autoclass:: pcapkit.protocols.internet.ipv4.protocol.IPv4
   :no-members:
   :show-inheritance:

   .. autoattribute:: __option__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make
   .. automethod:: unpack
   .. automethod:: id
   .. automethod:: register_option

   .. automethod:: __index__
   .. automethod:: __post_init__

   .. automethod:: _make_data
   .. automethod:: _read_ipv4_options
   .. automethod:: _make_ipv4_options
   .. automethod:: _read_opt_unassigned
   .. automethod:: _read_opt_eool
   .. automethod:: _read_opt_nop
   .. automethod:: _read_opt_rr
   .. automethod:: _read_opt_mtup
   .. automethod:: _read_opt_mtur
   .. automethod:: _read_opt_qs
   .. automethod:: _read_opt_ts
   .. automethod:: _read_opt_tr
   .. automethod:: _read_opt_sec
   .. automethod:: _read_opt_lsr
   .. automethod:: _read_opt_e_sec
   .. automethod:: _read_opt_sid
   .. automethod:: _read_opt_ssr
   .. automethod:: _read_opt_rtralt
   .. automethod:: _make_opt_unassigned
   .. automethod:: _make_opt_eool
   .. automethod:: _make_opt_nop
   .. automethod:: _make_opt_rr
   .. automethod:: _make_opt_mtup
   .. automethod:: _make_opt_mtur
   .. automethod:: _make_opt_qs
   .. automethod:: _make_opt_ts
   .. automethod:: _make_opt_tr
   .. automethod:: _make_opt_sec
   .. automethod:: _make_opt_lsr
   .. automethod:: _make_opt_e_sec
   .. automethod:: _make_opt_sid
   .. automethod:: _make_opt_ssr
   .. automethod:: _make_opt_rtralt

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipv4.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv4``, with no alias: the module moved here
   (:issue:`2534`).

.. autodata:: pcapkit.protocols.internet.ipv4.schema.IPV4_HEADER_LEN

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.IPv4
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.EOOLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.NOPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.SECOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.LSROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.TSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.ESECOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.RROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.SIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.SSROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.MTUPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.MTUROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.TROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.RTRALTOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema._QSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.QSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.QuickStartRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.QuickStartReportOption
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.VerIHLField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.ToSField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.TSFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.QuickStartFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.QSTestFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.schema.QSNonce
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.ipv4.schema.quick_start_option_length

.. autofunction:: pcapkit.protocols.internet.ipv4.schema.quick_start_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipv4.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipv4``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv4.data.IPv4
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.ToSField
   :members:
   :show-inheritance:

   .. attribute:: del
      :type: pcapkit.const.ipv4.tos_del.ToSDelay

      Delay.

      .. note::

         This field's name conflicts with the :keyword:`del` keyword, so
         access it with :func:`getattr` instead.

.. autoclass:: pcapkit.protocols.internet.ipv4.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.OptionType
   :members:
   :show-inheritance:

   .. attribute:: class
      :type: pcapkit.const.ipv4.option_class.OptionClass

      Option class.

      .. note::

         This field's name conflicts with the :keyword:`class` keyword, so
         access it with :func:`getattr` instead.

.. autoclass:: pcapkit.protocols.internet.ipv4.data.UnassignedOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.EOOLOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.NOPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.SECOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.LSROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.TSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.ESECOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.RROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.SIDOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.SSROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.MTUPOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.MTUROption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.TROption
   :members:
   :show-inheritance:

   .. attribute:: return
      :type: int

      Return hop count.

      .. note::

         This field's name conflicts with the :keyword:`return` keyword, so
         access it with :func:`getattr` instead.

.. autoclass:: pcapkit.protocols.internet.ipv4.data.RTRALTOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.QSOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.QuickStartRequestOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv4.data.QuickStartReportOption
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPv4
