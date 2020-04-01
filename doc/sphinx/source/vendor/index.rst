Web Crawlers for Constant Enumerations
======================================

Subpackages
-----------

.. toctree::
   :maxdepth: 4

   vendor/arp
   vendor/ftp
   vendor/hip
   vendor/http
   vendor/ipv4
   vendor/ipv6
   vendor/ipx
   vendor/mh
   vendor/ospf
   vendor/reg
   vendor/tcp
   vendor/vlan

Base Generator
--------------

.. automodule:: pcapkit.vendor.default
   :members:
   :undoc-members:
   :show-inheritance:

Command Line Tool
-----------------

.. code::

   usage: pcapkit-vendor [-h] [-V] ...

   update constant enumerations

   positional arguments:
     target         update targets, supply none to update all

   optional arguments:
     -h, --help     show this help message and exit
     -V, --version  show program's version number and exit

.. automodule:: pcapkit.vendor.__main__
   :members:
   :undoc-members:
   :show-inheritance:
