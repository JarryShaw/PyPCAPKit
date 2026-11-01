Constant Enumerations
=====================

.. module:: pcapkit.const

This module contains all constant enumerations of :mod:`pcapkit`, which are
automatically generated from the :mod:`pcapkit.vendor` module.

.. _unrecognised-values:

Unrecognised Values
-------------------

Nearly every :term:`registry` below departs from :mod:`enum` in one deliberate way, and it
is the behaviour to know about before using any of them: looking one up by a value
it does not define does **not** raise. Its ``_missing_`` override returns a
member-like object for a value that falls in one of the registry's unassigned or
reserved bands, named for that band. Only a value no band covers, or of the wrong
type, raises :exc:`ValueError`.

In almost every registry that object is **not** installed: the registry does not
grow, and a second lookup of the same value returns an equal but distinct object.
Some behave otherwise, and :ref:`mint-criterion` gives the full split:

* :class:`~pcapkit.const.mh.cga_type.CGAType` installs a permanent member, so
  ``__members__`` and iteration grow.
* :class:`~pcapkit.const.tcp.flags.Flags` and the Mobility Header flag
  registries, such as
  :class:`~pcapkit.const.mh.binding_ack_flag.BindingACKFlag`, hand back to
  |aenum|_'s flag base, which caches the composed object in the value lookup
  table only: a second lookup returns the same object, while ``__members__``
  and iteration are unchanged.
* :class:`~pcapkit.const.hip.transport.Transport`,
  :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader`,
  :class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` and the memberless
  :class:`~pcapkit.const.reg.apptype.apptype.AppType` base raise
  :exc:`ValueError` for any unknown value.

That is what makes the enumerations usable against live capture data, where a
protocol number assigned after this release was generated is a routine
occurrence rather than an error. It also means an enumeration is not a
closed set: an unassigned value resolves to a member that is, apart from
:class:`~pcapkit.const.mh.cga_type.CGAType`, absent from iteration and ``__members__``,
and whether a repeat lookup returns the same object varies by registry, so compare such
members by value, not identity.

The common form of the override is generated -- see :mod:`pcapkit.vendor.default`,
whose template emits it -- while the valid range and the names of the unassigned
bands are per-registry, taken from that registry's own source data. The individual
overrides are therefore not documented per class.

.. seealso::

   :doc:`../foundation/registry` covers the other half of extending a registry:
   once a code exists, registering a parser class, schema or engine against it.

Protocol Numbers
----------------

.. toctree::
   :maxdepth: 2

   reg

Link Layer
----------

.. toctree::
   :maxdepth: 2

   arp
   l2tp
   linux
   vlan

Internet Layer
--------------

.. toctree::
   :maxdepth: 2

   esp
   hip
   icmp
   icmpv6
   igmp
   ipv4
   ipv6
   ipx
   mh

Transport Layer
---------------

.. toctree::
   :maxdepth: 2

   sctp
   tcp

Application Layer
-----------------

.. toctree::
   :maxdepth: 2

   ftp
   http
   ngap
   ospf
   sslv2
   tls

Miscellaneous
-------------

.. toctree::
   :maxdepth: 2

   pcapng
