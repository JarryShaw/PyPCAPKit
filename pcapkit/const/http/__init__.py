# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.http.HTTP` Constant Enumerations
=============================================================================

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.http.HTTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`HTTP_ErrorCode <pcapkit.const.http.error_code.ErrorCode>`
     - HTTP/2 Error Code [*]_
   * - :class:`HTTP_Frame <pcapkit.const.http.frame.Frame>`
     - HTTP/2 Frame Type [*]_
   * - :class:`HTTP_Setting <pcapkit.const.http.setting.Setting>`
     - HTTP/2 Settings [*]_

.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type
.. [*] https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings

"""

from pcapkit.const.http.error_code import ErrorCode as HTTP_ErrorCode
from pcapkit.const.http.frame import Frame as HTTP_Frame
from pcapkit.const.http.setting import Setting as HTTP_Setting

__all__ = ['HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Setting']
