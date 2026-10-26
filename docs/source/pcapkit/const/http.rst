=======================================================================
:class:`~pcapkit.protocols.application.http.HTTP` Constant Enumerations
=======================================================================

.. module:: pcapkit.const.http

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.http.HTTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`HTTP_ErrorCode <pcapkit.const.http.error_code.ErrorCode>`
     - HTTP/2 Error Code [*]_
   * - :class:`HTTP_Frame <pcapkit.const.http.frame.Frame>`
     - HTTP/2 Frame Type [*]_
   * - :class:`HTTP_Method <pcapkit.const.http.method.Method>`
     - HTTP/1.\* Method [*]_
   * - :class:`HTTP_Setting <pcapkit.const.http.setting.Setting>`
     - HTTP/2 Settings [*]_
   * - :class:`HTTP_Status <pcapkit.const.http.status_code.StatusCode>`
     - HTTP/1.\* Status Code [*]_

HTTP/2 Error Code
=================

.. module:: pcapkit.const.http.error_code

This module contains the constant enumeration for **HTTP/2 Error Code**,
which is automatically generated from :class:`pcapkit.vendor.http.error_code.ErrorCode`.

.. autoclass:: pcapkit.const.http.error_code.ErrorCode
   :members:
   :undoc-members:
   :show-inheritance:

HTTP/2 Frame Type
=================

.. module:: pcapkit.const.http.frame

This module contains the constant enumeration for **HTTP/2 Frame Type**,
which is automatically generated from :class:`pcapkit.vendor.http.frame.Frame`.

.. autoclass:: pcapkit.const.http.frame.Frame
   :members:
   :undoc-members:
   :show-inheritance:

HTTP Method
===========

.. module:: pcapkit.const.http.method

This module contains the constant enumeration for **HTTP Method**,
which is automatically generated from :class:`pcapkit.vendor.http.method.Method`.

.. versionchanged:: 1.5.0

   Neither :meth:`Method._missing_ <pcapkit.const.http.method.Method._missing_>` nor
   :meth:`Method.get() <pcapkit.const.http.method.Method.get>` mints a member
   (:issue:`860`): only IANA-registered values are members, and a new one is created
   through :meth:`~pcapkit.corekit.enum.EnumRegistry.register`, which can supply the
   ``safe`` and ``idempotent`` a bare wire method verb carries neither of. A member's
   :class:`str` payload is its value, so ``Method.GET == 'GET'`` (:issue:`870`).

   :meth:`Method.get() <pcapkit.const.http.method.Method.get>` matches ``key``
   case-sensitively, as :rfc:`9110` makes the method token (:issue:`896`), and checks it
   against member values as well as names (:issue:`908`). A non-:class:`str` ``key``
   raises :exc:`ValueError` (:issue:`908`): ``get(42)`` and ``get(None)`` raised
   :exc:`AttributeError` from ``key.upper()``, and ``get(b'GET')`` raised
   :exc:`TypeError`.

   :meth:`Method._missing_ <pcapkit.const.http.method.Method._missing_>` also checks a
   folded ``value`` against member values, not only names, so a hyphenated method such
   as ``'baseline-control'`` resolves to :attr:`Method.BASELINE_CONTROL`, with the
   registered ``safe`` and ``idempotent``, in any case (:issue:`2284`).

.. autoclass:: pcapkit.const.http.method.Method
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __new__

HTTP/2 Settings
===============

.. module:: pcapkit.const.http.setting

This module contains the constant enumeration for **HTTP/2 Settings**,
which is automatically generated from :class:`pcapkit.vendor.http.setting.Setting`.

.. autoclass:: pcapkit.const.http.setting.Setting
   :members:
   :undoc-members:
   :show-inheritance:

HTTP Status Code
================

.. module:: pcapkit.const.http.status_code

This module contains the constant enumeration for **HTTP Status Code**,
which is automatically generated from :class:`pcapkit.vendor.http.status_code.StatusCode`.

.. autoclass:: pcapkit.const.http.status_code.StatusCode
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __new__, __str__

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type
.. [*] https://www.iana.org/assignments/http-methods/http-methods.xhtml#methods
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings
.. [*] https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml#http-status-codes-1
