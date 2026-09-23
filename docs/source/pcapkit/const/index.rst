Constant Enumerations
=====================

.. module:: pcapkit.const

This module contains all constant enumerations of :mod:`pcapkit`, which are
automatically generated from the :mod:`pcapkit.vendor` module.

.. _unrecognised-values:

Unrecognised Values
-------------------

Every enumeration below departs from :mod:`enum` in one deliberate way, and it is
the behaviour to know about before using any of them: looking one up by a value
the registry does not define does **not** raise. Each class overrides
``_missing_`` so that a value inside the registry's valid range is minted into a
new member on the fly -- via ``aenum.extend_enum``, named for the unassigned or
reserved band it falls in -- and returned. Only a value outside that range, or of
the wrong type, raises :exc:`ValueError`.

That is what makes the enumerations usable against live capture data, where a
protocol number assigned after this release was generated is a routine
occurrence rather than an error. It also means an enumeration member is not a
closed set: the identity of a minted member is stable for the life of the
process, but it does not exist until something asks for it.

The mechanism is uniform because it is generated -- see
:mod:`pcapkit.vendor.default`, whose template emits the ``_missing_`` override
for every registry -- while the valid range and the names of the unassigned bands
are per-registry, taken from that registry's own IANA data. The individual
overrides are therefore not documented per class.

.. seealso::

   :doc:`../foundation/registry` covers the other half of extending a registry:
   once a code exists, registering a parser class, schema or engine against it.

Protocol Numbers
----------------

.. toctree::
   :maxdepth: 2

   reg

Miscellanous
------------

.. toctree::
   :maxdepth: 2

   pcapng

Link Layer
----------

.. toctree::
   :maxdepth: 2

   arp
   l2tp
   ospf
   vlan

Internet Layer
--------------

.. toctree::
   :maxdepth: 2

   esp
   hip
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
