IP Address Conversion
=====================

.. module:: pcapkit.corekit.schema.ipaddress

:mod:`pcapkit.corekit.schema.ipaddress` converts a caller-supplied IP address to an
:mod:`ipaddress` object, refusing a :obj:`bool` before :mod:`ipaddress` reads it as
an :class:`int` (:issue:`491`), for the IP address fields
(:mod:`pcapkit.corekit.fields.ipaddress`) and the protocols' makers alike.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.corekit.fields.ipaddress``, with the guards the
   IP address fields share (:issue:`2674`).

Construction Helpers
--------------------

.. autofunction:: pcapkit.corekit.schema.ipaddress.parse_ip_address

Internal Definitions
--------------------

.. autofunction:: pcapkit.corekit.schema.ipaddress._reject_bool
