HTTP - Hypertext Transfer Protocol
==================================

.. module:: pcapkit.protocols.application.http

:mod:`pcapkit.protocols.application.http` contains
:class:`~pcapkit.protocols.application.http.HTTP`,
which is a base class for Hypertext Transfer
Protocol (HTTP) [*]_ family, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.HTTP>`
and :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTP>`,
and :func:`~pcapkit.protocols.application.http.test_start_line`,
which tells whether a payload opens with an HTTP/1.* start line.

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

   .. autoattribute:: _preface_length

.. autofunction:: pcapkit.protocols.application.http.test_start_line

.. autodata:: pcapkit.protocols.application.http._HTTP2_PREFACE

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
