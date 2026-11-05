===============
Vendor Crawlers
===============

.. module:: pcapkit.vendor

The crawlers that generate :mod:`pcapkit.const`. They need the ``vendor`` extra,
``pip install "pypcapkit[vendor]"``.

.. versionchanged:: 1.5.0

   Without ``requests`` or ``beautifulsoup4``, importing this package succeeds
   but imports no crawler, where it used to raise. Reading a name in its
   ``__all__``, or :class:`~pcapkit.vendor.default.Vendor`, raises
   :exc:`ModuleNotFoundError` naming the missing packages and the extra
   (:issue:`1850`). Importing a crawler module directly, such as
   :mod:`pcapkit.vendor.reg`, still raises the missing package's own
   :exc:`ModuleNotFoundError`.

Crawler Implementations
=======================

.. toctree::
   :maxdepth: 2

   default

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
   ieee802_11
   l2tp
   linux
   radiotap
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

   dccp
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

Command Line Tool
=================

.. module:: pcapkit.vendor.__main__

:program:`pcapkit-vendor` regenerates the constant enumerations.

.. code-block::

   usage: pcapkit-vendor [-h] [-V] ...

   update constant enumerations

   positional arguments:
     target         update targets, supply none to update all

   options:
     -h, --help     show this help message and exit
     -V, --version  show program's version number and exit

.. versionchanged:: 1.5.0

   Without ``requests`` or ``beautifulsoup4`` from the ``vendor`` extra,
   :program:`pcapkit-vendor` writes one line to standard error naming the
   missing packages and the extra to install, and exits with status ``1``
   before any target runs (:issue:`1850`). It used to fail with a traceback.
   ``--help`` and ``--version`` work without them.
