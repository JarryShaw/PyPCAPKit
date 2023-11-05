HTTP - Hypertext Transfer Protocol
==================================

.. module:: pcapkit.protocols.application.http

:mod:`pcapkit.protocols.application.http` contains
:class:`~pcapkit.protocols.application.http.HTTP`
only, which is a base class for Hypertext Transfer
Protocol (HTTP) [*]_ family, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.application.httpv1>`
and :class:`HTTP/2 <pcapkit.protocols.application.application.httpv2>`.

.. autoclass:: pcapkit.protocols.application.http.HTTP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: version

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _guess_version

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
