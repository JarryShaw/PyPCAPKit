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
   .. autoattribute:: PROTO_DEST

   .. automethod:: count
   .. automethod:: process
   .. automethod:: context

   .. automethod:: wrap_comment
   .. automethod:: safe_name
   .. automethod:: rename

   .. automethod:: request
   .. automethod:: _request
   .. automethod:: _dest_path

   .. automethod:: __init__

Running a Crawler
-----------------

Instantiating a crawler fetches its registry and writes the constant module:

.. mermaid::

   flowchart TD
       NEW["a crawler instantiated: Vendor.\_\_init\_\_"]
       L{"LINK set?"}
       G["GET LINK<br/>a non-OK or empty page retried,<br/>up to MAX\_RETRY"]
       P{"get\_proxies() gives any?"}
       GP["GET LINK through the proxies<br/>retried the same way"]
       CI{"PCAPKIT\_CI\_MODE on?"}
       TTY{"stdin interactive?"}
       RAISE["the request error is raised"]
       MAN["manual: LINK opened in a browser,<br/>wait for its saved page source"]
       REQ["request(text): the registry's records"]
       CNT["count(data)"]
       CTX["context(data): process(), then the module template"]
       DEST["\_dest\_path(): the matching module under pcapkit/const/"]
       WR["the constant module written"]

       NEW --> L
       L -->|"no: request() with no text"| REQ
       L -->|yes| G
       G -->|ok| REQ
       G -->|fails| P
       P -->|yes| GP
       P -->|no| CI
       GP -->|ok| REQ
       GP -->|fails| CI
       CI -->|yes| RAISE
       CI -->|no| TTY
       TTY -->|no| RAISE
       TTY -->|yes| MAN --> REQ
       REQ --> CNT --> CTX --> DEST --> WR

       click NEW "default.html#pcapkit.vendor.default.Vendor.__init__"
       click REQ "default.html#pcapkit.vendor.default.Vendor.request"
       click CNT "default.html#pcapkit.vendor.default.Vendor.count"
       click CTX "default.html#pcapkit.vendor.default.Vendor.context"
       click DEST "default.html#pcapkit.vendor.default.Vendor._dest_path"

Each failed fetch warns with :class:`~pcapkit.utilities.warnings.VendorRequestWarning`;
:envvar:`PCAPKIT_VENDOR_RETRY` sets :data:`~pcapkit.vendor.default.MAX_RETRY`, and
:envvar:`PCAPKIT_CI_MODE` turns on the CI check.

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

.. function:: LINE(NAME, DOCS, FLAG, ENUM, MISS, MODL, DEST=())

   Default constant template of enumeration registry from IANA CSV.

   :param str NAME: name of the constant enumeration class
   :param str DOCS: docstring for the constant enumeration class
   :param str FLAG: threshold value validator (range of valid values)
   :param str ENUM: enumeration data (class attributes)
   :param str MISS: missing value handler (default value)
   :param str MODL: module name of the constant enumeration class
   :param DEST: the crawler's :attr:`~pcapkit.vendor.default.Vendor.PROTO_DEST`,
      rendered as the class's ``__proto_dest__``; nothing is rendered when it is
      empty, which is the case for every registry that keys no ``__proto__``
   :type DEST: tuple[~pcapkit.corekit.module.ModuleDescriptor, ...]
   :rtype: str

.. autodata:: pcapkit.vendor.default.PROTO_DEST_IMPORT

.. autofunction:: pcapkit.vendor.default.render_proto_dest

.. autofunction:: pcapkit.vendor.default.get_proxies

.. autofunction:: pcapkit.vendor.default.stdin_is_interactive
