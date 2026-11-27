# -*- coding: utf-8 -*-
"""constants for DNS protocol

.. versionadded:: 1.7.0

.. versionremoved:: 1.9.0

   ``pcapkit.protocols.application.dns.const.POINTER_LIMIT``, now
   :data:`pcapkit.corekit.const.domain_name.POINTER_LIMIT` (:issue:`2934`).

"""

__all__ = ['HEADER_LENGTH']

#: Length of the fixed header, before the sections (:rfc:`1035#section-4.1.1`).
HEADER_LENGTH = 12
