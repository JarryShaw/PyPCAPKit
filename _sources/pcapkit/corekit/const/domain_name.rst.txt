Domain Name Constants
=====================

.. module:: pcapkit.corekit.const.domain_name

:mod:`pcapkit.corekit.const.domain_name` holds the domain name value the RFC fixes
and that code beyond DNS itself reads: the codec of
:mod:`pcapkit.corekit.schema.domain_name`. It is the one home of its value
(:issue:`1739`), and is not configurable.

.. versionadded:: 1.9.0

   Moved here from ``pcapkit.protocols.application.dns.const`` (:issue:`2934`).

.. autodata:: pcapkit.corekit.const.domain_name.POINTER_LIMIT
