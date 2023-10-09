# -*- coding: utf-8 -*-
# pylint: disable=unused-import
r""":class:`~pcapkit.protocols.application.http.HTTP` Vendor Crawlers
========================================================================

.. module:: pcapkit.vendor.http

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.http.HTTP` implementations. Available
crawlers include:

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

.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type
.. [*] https://www.iana.org/assignments/http-methods/http-methods.xhtml#methods
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings
.. [*] https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml#http-status-codes-1

"""

from pcapkit.vendor.http.error_code import ErrorCode as HTTP_ErrorCode
from pcapkit.vendor.http.frame import Frame as HTTP_Frame
from pcapkit.vendor.http.method import Method as HTTP_Method
from pcapkit.vendor.http.setting import Setting as HTTP_Setting
from pcapkit.vendor.http.status_code import StatusCode as HTTP_StatusCode

__all__ = ['HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Method', 'HTTP_Setting', 'HTTP_StatusCode']
