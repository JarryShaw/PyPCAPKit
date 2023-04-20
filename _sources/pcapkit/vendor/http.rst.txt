================================================================
:class:`~pcapkit.protocols.application.http.HTTP` Vendor Crawler
================================================================

.. module:: pcapkit.vendor.http


This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.http.HTTP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`HTTP_ErrorCode <pcapkit.vendor.http.error_code.ErrorCode>`
     - HTTP/2 Error Code [*]_
   * - :class:`HTTP_Frame <pcapkit.vendor.http.frame.Frame>`
     - HTTP/2 Frame Type [*]_
   * - :class:`HTTP_Method <pcapkit.vendor.http.method.Method>`
     - HTTP/1.\* Method [*]_
   * - :class:`HTTP_Setting <pcapkit.vendor.http.setting.Setting>`
     - HTTP/2 Settings [*]_
   * - :class:`HTTP_Status <pcapkit.vendor.http.status_code.StatusCode>`
     - HTTP/1.\* Status Code [*]_

HTTP/2 Error Code
=================

.. module:: pcapkit.vendor.http.error_code

This module contains the vendor crawler for **HTTP/2 Error Code**,
which is automatically generating :class:`pcapkit.+const+.http.error_code.ErrorCode`.

.. autoclass:: pcapkit.vendor.http.error_code.ErrorCode
   :members: FLAG, LINK
   :show-inheritance:

HTTP/2 Frame Type
=================

.. module:: pcapkit.vendor.http.frame

This module contains the vendor crawler for **HTTP/2 Frame Type**,
which is automatically generating :class:`pcapkit.+const+.http.frame.Frame`.

.. autoclass:: pcapkit.vendor.http.frame.Frame
   :members: FLAG, LINK
   :show-inheritance:

HTTP Method
===========

.. module:: pcapkit.vendor.http.method

This module contains the vendor crawler for **HTTP Method**,
which is automatically generating :class:`pcapkit.+const+.http.method.Method`.

.. autoclass:: pcapkit.vendor.http.method.Method
   :members: LINK
   :show-inheritance:

HTTP/2 Settings
===============

.. module:: pcapkit.vendor.http.setting

This module contains the vendor crawler for **HTTP/2 Settings**,
which is automatically generating :class:`pcapkit.+const+.http.setting.Setting`.

.. autoclass:: pcapkit.vendor.http.setting.Setting
   :members: FLAG, LINK
   :show-inheritance:

HTTP Status Code
================

.. module:: pcapkit.vendor.http.status_code

This module contains the vendor crawler for **HTTP Status Code**,
which is automatically generating :class:`pcapkit.+const+.http.status_code.StatusCode`.

.. autoclass:: pcapkit.vendor.http.status_code.StatusCode
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type
.. [*] https://www.iana.org/assignments/http-methods/http-methods.xhtml#methods
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings
.. [*] https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml#http-status-codes-1
