Base Crawler
============

.. module:: pcapkit.vendor.default

:mod:`pcapkit.vendor.default` contains :class:`~pcapkit.vendor.default.Vendor`
only, which is the base meta class for all vendor crawlers.

Vendor Crawler
--------------

.. autoclass:: pcapkit.vendor.default.Vendor
   :undoc-members:
   :show-inheritance:

   .. automethod:: __new__
   .. automethod:: __init__

   .. automethod:: wrap_comment
   .. automethod:: safe_name
   .. automethod:: rename
   .. automethod:: process
   .. automethod:: count
   .. automethod:: context
   .. automethod:: request

   .. automethod:: _request

   .. autoattribute:: NAME
   .. autoattribute:: DOCS
   .. autoattribute:: FLAG
      :no-value:
   .. autoattribute:: LINK
      :no-value:

Crawler Template
----------------

.. function:: pcapkit.vendor.default.LINE(NAME, DOCS, FLAG, ENUM, MISS, MODL)

   Default constant template of enumeration registry from IANA CSV.

   :param str NAME: name of the constant enumeration class
   :param str DOCS: docstring for the constant enumeration class
   :param str FLAG: threshold value validator (range of valid values)
   :param str ENUM: enumeration data (class attributes)
   :param str MISS: missing value handler (default value)
   :param str MODL: module name of the constant enumeration class
   :rtype: str

Crawler Proxy
-------------

.. autofunction:: pcapkit.vendor.default.get_proxies
