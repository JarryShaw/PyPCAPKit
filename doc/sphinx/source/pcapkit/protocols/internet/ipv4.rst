IPv4 - Internet Protocol version 4
==================================

.. module:: pcapkit.protocols.internet.ipv4
.. module:: pcapkit.protocols.data.internet.ipv4

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

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.ipv4.IPv4
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make
   .. automethod:: id

   .. automethod:: _read_ipv4_addr
   .. automethod:: _read_ipv4_opt_type

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

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.ipv4.IPv4(version, hdr_len, tos, len, id, flags, offset, ttl, protocol, checksum, src, dst)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: version
   .. autoattribute:: hdr_len
   .. autoattribute:: tos
   .. autoattribute:: len
   .. autoattribute:: id
   .. autoattribute:: flags
   .. autoattribute:: offset
   .. autoattribute:: ttl
   .. autoattribute:: protocol
   .. autoattribute:: checksum
   .. autoattribute:: src
   .. autoattribute:: dst
   .. autoattribute:: options

.. autoclass:: pcapkit.protocols.data.internet.ipv4.ToSField(pre, del, thr, rel, ecn)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: pre

   .. attribute:: del
      :type: ToSDelay

      Delay.

      .. note::

         This field is conflict with :keyword:`del` keyword. To access this field,
         directly use :func:`getattr` instead.

   .. autoattribute:: thr
   .. autoattribute:: rel
   .. autoattribute:: ecn

.. autoclass:: pcapkit.protocols.data.internet.ipv4.Flags(df, mf)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: df
   .. autoattribute:: mf

.. autoclass:: pcapkit.protocols.data.internet.ipv4.Option(code, length, type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: code
   .. autoattribute:: length
   .. autoattribute:: type

.. autoclass:: pcapkit.protocols.data.internet.ipv4.OptionType(change, class, number)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: change

   .. attribute:: class
      :type: OptionClass

      Option class.

      .. note::

         This field is conflict with :keyword:`class` keyword. To access this field,
         directly use :func:`getattr` instead.

   .. autoattribute:: number

.. autoclass:: pcapkit.protocols.data.internet.ipv4.UnassignedOption(code, length, type, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.internet.ipv4.EOOLOption(code, length, type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.NOPOption(code, length, type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv4.SECOption(code, length, type, level, flags)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: level
   .. autoattribute:: flags

.. autoclass:: pcapkit.protocols.data.internet.ipv4.LSROption(code, length, type, pointer, route)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: pointer
   .. autoattribute:: route

.. autoclass:: pcapkit.protocols.data.internet.ipv4.TSOption(code, length, type, pointer, overflow, flag, timestamp)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: pointer
   .. autoattribute:: overflow
   .. autoattribute:: flag
   .. autoattribute:: timestamp

.. autoclass:: pcapkit.protocols.data.internet.ipv4.ESECOption(code, length, type, level, flags)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: level
   .. autoattribute:: flags

.. autoclass:: pcapkit.protocols.data.internet.ipv4.RROption(code, length, type, pointer, route)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: pointer
   .. autoattribute:: route

.. autoclass:: pcapkit.protocols.data.internet.ipv4.SIDOption(code, length, type, sid)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: sid

.. autoclass:: pcapkit.protocols.data.internet.ipv4.SSROption(code, length, type, pointer, route)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: pointer
   .. autoattribute:: route

.. autoclass:: pcapkit.protocols.data.internet.ipv4.MTUPOption(code, length, type, mtu)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: mtu

.. autoclass:: pcapkit.protocols.data.internet.ipv4.MTUROption(code, length, type, mtu)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: mtu

.. autoclass:: pcapkit.protocols.data.internet.ipv4.TROption(code, length, type, id, outbound, return, originator)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: id
   .. autoattribute:: outbound

   .. attribute:: return
      :type: int

      Return hop count.

      .. note::

         This field is conflict with :keyword:`return` keyword. To access this field,
         directly use :func:`getattr` instead.

   .. autoattribute:: originator

.. autoclass:: pcapkit.protocols.data.internet.ipv4.RTRALTOption(code, length, type, alert)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: alert

.. autoclass:: pcapkit.protocols.data.internet.ipv4.QSOption(code, length, type, func, rate, ttl, nounce)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: func
   .. autoattribute:: rate
   .. autoattribute:: ttl
   .. autoattribute:: nounce

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv4
