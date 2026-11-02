SSLv3 - Secure Sockets Layer Version 3
======================================

.. module:: pcapkit.protocols.application.sslv3

:mod:`pcapkit.protocols.application.sslv3` contains
:class:`~pcapkit.protocols.application.sslv3.SSLv3` only,
which implements an extractor for Secure Sockets Layer
version 3 (SSLv3) [*]_, whose record is the one
:mod:`pcapkit.protocols.application.tls` describes.

Nothing dispatches to :class:`~pcapkit.protocols.application.sslv3.SSLv3`:
an SSLv3 record parses as :class:`~pcapkit.protocols.application.tls.TLS`
with alias ``SSLv3``.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.application.sslv3.SSLv3
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/rfc6101
