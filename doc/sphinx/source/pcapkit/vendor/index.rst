Vendor Crawlers
===============

.. module:: pcapkit.vendor

This module contains all web crawlers of :mod:`pcapkit`, which are
automatically generating from the :mod:`pcapkit.const` module's constant
enumerations.

Base Crawler
------------

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
   ospf
   vlan

Internet Layer
--------------

.. toctree::
   :maxdepth: 2

   hip
   ipv4
   ipv6
   ipx
   mh

Transport Layer
---------------

.. toctree::
   :maxdepth: 2

   tcp

Application Layer
-----------------

.. toctree::
   :maxdepth: 2

   ftp
   http

.. automodule:: pcapkit.vendor.__main__
   :no-members:

.. code-block::

   usage: pcapkit-vendor [-h] [-V] ...

   update constant enumerations

   positional arguments:
     target         update targets, supply none to update all

   optional arguments:
     -h, --help     show this help message and exit
     -V, --version  show program's version number and exit
