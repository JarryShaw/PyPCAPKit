:class:`~pcapkit.protocols.application.http.HTTP` Venddor Crawlers
==================================================================

.. module:: pcapkit.vendor.http

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.http.HTTP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`HTTP_ErrorCode <pcapkit.vendor.http.error_code.ErrorCode>`
     - HTTP/2 Error Code [*]_
   * - :class:`HTTP_Frame <pcapkit.vendor.http.frame.Frame>`
     - HTTP/2 Frame Type [*]_
   * - :class:`HTTP_Setting <pcapkit.vendor.http.setting.Setting>`
     - HTTP/2 Settings [*]_

.. automodule:: pcapkit.vendor.http.error_code
   :no-members:

.. autoclass:: pcapkit.vendor.http.error_code.ErrorCode
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.http.frame
   :no-members:

.. autoclass:: pcapkit.vendor.http.frame.Frame
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.http.setting
   :no-members:

.. autoclass:: pcapkit.vendor.http.setting.Setting
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings
