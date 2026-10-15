Base Crawler
============

.. module:: pcapkit.vendor.default

:mod:`pcapkit.vendor.default` exports :class:`~pcapkit.vendor.default.Vendor`
only, which is the base class for all vendor crawlers.

.. autoclass:: pcapkit.vendor.default.Vendor
   :no-members:
   :show-inheritance:

   .. autoattribute:: NAME
   .. autoattribute:: DOCS
   .. autoattribute:: FLAG
      :no-value:
   .. autoattribute:: LINK
      :no-value:

   .. automethod:: count
   .. automethod:: process
   .. automethod:: context

   .. automethod:: wrap_comment
   .. automethod:: safe_name
   .. automethod:: rename

   .. automethod:: request
   .. automethod:: _request
   .. automethod:: _dest_path

.. _vendor-variables:

Environment Variables
---------------------

The crawlers' variables are read here, not by :mod:`pcapkit.utilities.config`
(:issue:`1726`). :envvar:`PCAPKIT_VENDOR_RETRY` and :envvar:`PCAPKIT_CI_MODE`
are read once, when this module is imported, with
:func:`~pcapkit.utilities.config.read_limit` and
:func:`~pcapkit.utilities.config.read_flag`: a bad value warns with a
:exc:`~pcapkit.utilities.warnings.ConfigWarning`, naming the variable and the
value, and falls back to the default. The proxy addresses are read by
:func:`~pcapkit.vendor.default.get_proxies` on every call, so a proxy set after
the import is still honoured.

.. envvar:: PCAPKIT_VENDOR_RETRY

   Sets :data:`~pcapkit.vendor.default.MAX_RETRY`: an integer ``>= 1``, default
   ``5``.

.. envvar:: PCAPKIT_CI_MODE

   Sets :data:`~pcapkit.vendor.default.CI_MODE`: ``1``/``yes``/``true``/``on``
   or ``0``/``no``/``false``/``off``, default off.

.. envvar:: PCAPKIT_HTTP_PROXY

   The HTTP proxy address for the crawlers, read by
   :func:`~pcapkit.vendor.default.get_proxies` on every call. Unset by default.

.. envvar:: PCAPKIT_HTTPS_PROXY

   The HTTPS proxy address for the crawlers, read by
   :func:`~pcapkit.vendor.default.get_proxies` on every call. Unset by default.

.. autodata:: pcapkit.vendor.default.MAX_RETRY
.. autodata:: pcapkit.vendor.default.CI_MODE

Internal Definitions
--------------------

.. autoclass:: pcapkit.vendor.default.VendorMeta
   :no-members:
   :show-inheritance:

.. function:: LINE(NAME, DOCS, FLAG, ENUM, MISS, MODL)

   Default constant template of enumeration registry from IANA CSV.

   :param str NAME: name of the constant enumeration class
   :param str DOCS: docstring for the constant enumeration class
   :param str FLAG: threshold value validator (range of valid values)
   :param str ENUM: enumeration data (class attributes)
   :param str MISS: missing value handler (default value)
   :param str MODL: module name of the constant enumeration class
   :rtype: str

.. autofunction:: pcapkit.vendor.default.get_proxies
