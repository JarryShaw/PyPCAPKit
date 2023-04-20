IPv4 - Internet Protocol version 4
==================================

.. module:: pcapkit.protocols.internet.ipv4

:mod:`pcapkit.protocols.internet.ipv4` contains
:class:`~pcapkit.protocols.internet.ipv4.IPv4` only,
which implements extractor for Internet Protocol
version 4 (IPv4) [*]_, whose structure is described
as below:

======= ========= ====================== =============================================
Octets      Bits        Name                    Description
======= ========= ====================== =============================================
  0           0   ``ip.version``              Version (``4``)
  0           4   ``ip.hdr_len``              Internal Header Length (IHL)
  1           8   ``ip.dsfield.dscp``         Differentiated Services Code Point (DSCP)
  1          14   ``ip.dsfield.ecn``          Explicit Congestion Notification (ECN)
  2          16   ``ip.len``                  Total Length
  4          32   ``ip.id``                   Identification
  6          48                               Reserved Bit (must be ``\x00``)
  6          49   ``ip.flags.df``             Don't Fragment (DF)
  6          50   ``ip.flags.mf``             More Fragments (MF)
  6          51   ``ip.frag_offset``          Fragment Offset
  8          64   ``ip.ttl``                  Time To Live (TTL)
  9          72   ``ip.proto``                Protocol (Transport Layer)
  10         80   ``ip.checksum``             Header Checksum
  12         96   ``ip.src``                  Source IP Address
  16        128   ``ip.dst``                  Destination IP Address
  20        160   ``ip.options``              IP Options (if IHL > ``5``)
======= ========= ====================== =============================================

.. autoclass:: pcapkit.protocols.internet.ipv4.IPv4
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: id
   .. automethod:: register_option

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _read_ipv4_options
   .. automethod:: _read_opt_unassigned
   .. automethod:: _read_opt_eool
   .. automethod:: _read_opt_nop
   .. automethod:: _read_opt_sec
   .. automethod:: _read_opt_lsr
   .. automethod:: _read_opt_ts
   .. automethod:: _read_opt_esec
   .. automethod:: _read_opt_rr
   .. automethod:: _read_opt_sid
   .. automethod:: _read_opt_ssr
   .. automethod:: _read_opt_mtup
   .. automethod:: _read_opt_mtur
   .. automethod:: _read_opt_tr
   .. automethod:: _read_opt_rtralt
   .. automethod:: _read_opt_qs

   .. automethod:: _make_ipv4_options
   .. automethod:: _make_opt_unassigned
   .. automethod:: _make_opt_eool
   .. automethod:: _make_opt_nop
   .. automethod:: _make_opt_sec
   .. automethod:: _make_opt_lsr
   .. automethod:: _make_opt_ts
   .. automethod:: _make_opt_esec
   .. automethod:: _make_opt_rr
   .. automethod:: _make_opt_sid
   .. automethod:: _make_opt_ssr
   .. automethod:: _make_opt_mtup
   .. automethod:: _make_opt_mtur
   .. automethod:: _make_opt_tr
   .. automethod:: _make_opt_rtralt
   .. automethod:: _make_opt_qs

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ipv4

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.IPv4
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.UnassignedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.EOOLOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.NOPOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.SECOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.LSROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.TSOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.ESECOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.RROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.SIDOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.SSROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.MTUPOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.MTUROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.TROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.RTRALTOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.QSOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.VerIHLField
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.ToSField
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.Flags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.TSFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.QuickStartFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.QSTestFlags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv4.QSNonce
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.internet.ipv4.quick_start_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ipv4

.. autoclass:: pcapkit.protocols.data.internet.ipv4.IPv4
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.ToSField
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. attribute:: del
      :type: ToSDelay

      Delay.

      .. note::

         This field is conflict with :keyword:`del` keyword. To access this field,
         directly use :func:`getattr` instead.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.Flags
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.Option
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.OptionType
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. attribute:: class
      :type: OptionClass

      Option class.

      .. note::

         This field is conflict with :keyword:`class` keyword. To access this field,
         directly use :func:`getattr` instead.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.UnassignedOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.EOOLOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.NOPOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.SECOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.LSROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.TSOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.ESECOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.RROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.SIDOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.SSROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.MTUPOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.MTUROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.TROption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. attribute:: return
      :type: int

      Return hop count.

      .. note::

         This field is conflict with :keyword:`return` keyword. To access this field,
         directly use :func:`getattr` instead.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.RTRALTOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.QSOption
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv4
