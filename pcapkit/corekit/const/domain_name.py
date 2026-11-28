# -*- coding: utf-8 -*-
"""Domain Name Constants
===========================

.. module:: pcapkit.corekit.const.domain_name

:mod:`pcapkit.corekit.const.domain_name` holds the domain name value the RFC
fixes and that code beyond DNS itself reads: the domain name codec of
:mod:`pcapkit.corekit.schema.domain_name`. It is the one home of its value
(:issue:`1739`), and is not configurable. It is one topic of
:mod:`pcapkit.corekit.const`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.9.0

   Moved here from ``pcapkit.protocols.application.dns.const`` (:issue:`2934`).

"""

__all__ = ['POINTER_LIMIT']

#: Largest offset a compression pointer can carry, in its 14 bits
#: (:rfc:`1035#section-4.1.4`).
POINTER_LIMIT = 0x3FFF
