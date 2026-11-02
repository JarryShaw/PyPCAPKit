===============
Vendor Crawlers
===============

.. module:: pcapkit.vendor

This module contains all web crawlers of :mod:`pcapkit`, which
automatically generate the :mod:`pcapkit.const` module's constant
enumerations.

The crawlers need the ``vendor`` extra, ``pip install "pypcapkit[vendor]"``.

.. versionchanged:: 1.5.0

   Without ``requests`` or ``beautifulsoup4``, which the crawlers import at
   module scope, importing this package succeeds and imports no crawler.
   Reading any name in its ``__all__``, or
   :class:`~pcapkit.vendor.default.Vendor`, then raises
   :exc:`ModuleNotFoundError` naming the missing packages and the extra to
   install (:issue:`1850`). Importing a crawler module directly, such as
   :mod:`pcapkit.vendor.reg`, still raises the missing package's own
   :exc:`ModuleNotFoundError`. Before, importing this package raised it.

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

:mod:`pcapkit.vendor.__main__` is a command line tool for updating
constant enumerations.

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
