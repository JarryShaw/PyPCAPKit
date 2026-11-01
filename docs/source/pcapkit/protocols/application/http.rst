HTTP - Hypertext Transfer Protocol
==================================

.. module:: pcapkit.protocols.application.http

:mod:`pcapkit.protocols.application.http` contains
:class:`~pcapkit.protocols.application.http.HTTP`,
which is a base class for Hypertext Transfer
Protocol (HTTP) [*]_ family, e.g.
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.HTTPv1>`
and :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTPv2>`,
and :func:`~pcapkit.protocols.application.http.test_start_line`,
which tells whether a payload opens with an HTTP/1.* start line.

.. versionchanged:: 1.6.0

   A payload a transport port binds to
   :class:`~pcapkit.protocols.application.http.HTTP` is parsed by
   :class:`~pcapkit.protocols.application.httpv1.HTTPv1` or
   :class:`~pcapkit.protocols.application.httpv2.HTTPv2`, which
   :meth:`~pcapkit.protocols.application.http.HTTP._dispatch_version` picks,
   rather than by this class, so its data sits under ``httpv1`` or ``httpv2``
   rather than ``http`` (:issue:`2524`).

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
   .. automethod:: _dispatch_version

   .. autoattribute:: _preface_length

   .. automethod:: from_data

.. autofunction:: pcapkit.protocols.application.http.test_start_line

.. autodata:: pcapkit.protocols.application.http._HTTP2_PREFACE

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
