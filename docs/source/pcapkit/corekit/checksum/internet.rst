Internet Checksum
=================

.. module:: pcapkit.corekit.checksum.internet

:mod:`pcapkit.corekit.checksum.internet` contains the one's-complement
Internet checksum (:rfc:`1071`) of the IPv4 header, TCP, UDP, ICMP, ICMPv6
and OSPF. Parsing verifies a checksum only if
:data:`~pcapkit.utilities.config.CHECKSUM_VERIFY` is on, and records the
outcome as ``checksum_status``; construction computes one left out unless
:data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is off (:issue:`2471`).
A mismatch warns with a :exc:`~pcapkit.utilities.warnings.ChecksumWarning`,
which a filter can silence alone (:issue:`2470`).

It imports nothing from :mod:`pcapkit.protocols`, which builds on it
(:issue:`2580`). A checksum over the IP pseudo-header is left to the enclosing
IP layer, see :mod:`pcapkit.protocols.misc.checksum.ip_pseudo`. ICMP's
checksum, over the message alone, is verified as it is parsed, unless the IP
layer it is parsed from is a fragment, see :func:`fragment_payload`.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.corekit.checksum.internet.ChecksumStatus
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.corekit.checksum.internet.internet_checksum
.. autofunction:: pcapkit.corekit.checksum.internet.compute_checksum
.. autofunction:: pcapkit.corekit.checksum.internet.partial_checksum
.. autofunction:: pcapkit.corekit.checksum.internet.verify_checksum
.. autofunction:: pcapkit.corekit.checksum.internet.fragment_payload
