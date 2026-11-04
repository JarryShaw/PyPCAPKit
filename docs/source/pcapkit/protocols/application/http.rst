HTTP - Hypertext Transfer Protocol
==================================

.. module:: pcapkit.protocols.application.http
.. module:: pcapkit.protocols.application.http.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.application.http._HTTP2_PREFACE`` and
   ``pcapkit.protocols.application.http.test_start_line``, with no alias: they are in
   this module, and :mod:`pcapkit.protocols.application.http` exports the protocol class
   alone (:issue:`2534`).

:mod:`pcapkit.protocols.application.http.protocol` contains
:class:`~pcapkit.protocols.application.http.protocol.HTTP`,
which is a base class for Hypertext Transfer
Protocol (HTTP) [*]_ family, e.g.
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.protocol.HTTPv1>`
and :class:`HTTP/2 <pcapkit.protocols.application.httpv2.protocol.HTTPv2>`,
and :func:`~pcapkit.protocols.application.http.protocol.test_start_line`,
which tells whether a payload opens with an HTTP/1.* start line.

.. versionchanged:: 1.6.0

   A payload a transport port binds to
   :class:`~pcapkit.protocols.application.http.protocol.HTTP`, and constructing or
   rebuilding that class, give
   :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
   :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2` rather than an instance
   of it, so the data sits under ``httpv1`` or ``httpv2`` rather than ``http``
   (:issue:`2524`). Building it from fields takes ``version`` and is refused
   without it, where it built HTTP/1.*, and its
   :meth:`~pcapkit.protocols.application.http.protocol.HTTP.from_data` refuses a
   :obj:`dict`, where it read the ``receipt`` or ``sid`` key (:issue:`2628`).

.. autoclass:: pcapkit.protocols.application.http.protocol.HTTP
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

   .. automethod:: __index__
   .. automethod:: __init__
   .. automethod:: __new__

   .. automethod:: _guess_version
   .. automethod:: _dispatch_version
   .. automethod:: _member_of_version

   .. autoattribute:: _preface_length

   .. automethod:: from_data

.. autofunction:: pcapkit.protocols.application.http.protocol.test_start_line

.. autodata:: pcapkit.protocols.application.http.protocol._HTTP2_PREFACE

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
