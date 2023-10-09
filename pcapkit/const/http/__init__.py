# -*- coding: utf-8 -*-
# pylint: disable=unused-import
r""":class:`~pcapkit.protocols.application.http.HTTP` Constant Enumerations
==============================================================================

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

.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type
.. [*] https://www.iana.org/assignments/http-methods/http-methods.xhtml#methods
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings
.. [*] https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml#http-status-codes-1

"""

from pcapkit.const.http.error_code import ErrorCode as HTTP_ErrorCode
from pcapkit.const.http.frame import Frame as HTTP_Frame
from pcapkit.const.http.method import Method as HTTP_Method
from pcapkit.const.http.setting import Setting as HTTP_Setting
from pcapkit.const.http.status_code import StatusCode as HTTP_Status

__all__ = ['HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Method', 'HTTP_Setting', 'HTTP_Status']
