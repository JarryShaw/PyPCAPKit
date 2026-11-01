HTTP/1.* - Hypertext Transfer Protocol
======================================

.. module:: pcapkit.protocols.application.httpv1

:mod:`pcapkit.protocols.application.httpv1` contains
:class:`~pcapkit.protocols.application.httpv1.HTTPv1`,
which implements an extractor for Hypertext Transfer
Protocol (HTTP/1.*) [*]_, and its
:class:`~pcapkit.protocols.application.httpv1.Type` enumeration. The
structure of an HTTP/1.* message is described as below:

.. code-block:: text

   METHOD URL HTTP/VERSION\r\n :==: REQUEST LINE
   <key> : <value>\r\n         :==: REQUEST HEADER
   ............  (Ellipsis)    :==: REQUEST HEADER
   \r\n                        :==: REQUEST SEPARATOR
   <body>                      :==: REQUEST BODY (optional)

   HTTP/VERSION CODE DESP \r\n :==: RESPONSE LINE
   <key> : <value>\r\n         :==: RESPONSE HEADER
   ............  (Ellipsis)    :==: RESPONSE HEADER
   \r\n                        :==: RESPONSE SEPARATOR
   <body>                      :==: RESPONSE BODY (optional)

.. versionchanged:: 1.5.0

   A message rebuilds byte for byte: the whitespace of the start line and
   header lines, and octets in them that are not UTF-8, are kept as captured
   rather than normalised or re-encoded (:issue:`1241`, :issue:`1302`,
   :issue:`1333`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.application.httpv1.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.application.httpv1.HTTPv1`,
   after its module (:issue:`2529`).

.. autoclass:: pcapkit.protocols.application.httpv1.HTTPv1
   :no-members:
   :show-inheritance:

   .. autoproperty:: alias
   .. autoproperty:: version

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _read_http_header
   .. automethod:: _read_http_body

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.application.httpv1.Type
   :members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.application.httpv1

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.httpv1.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.schema.application.httpv1.HTTPv1`,
   after its module (:issue:`2529`).

.. autoclass:: pcapkit.protocols.schema.application.httpv1.HTTPv1
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.application.httpv1

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.application.httpv1.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.data.application.httpv1.HTTPv1`,
   after its module (:issue:`2529`).

.. autoclass:: pcapkit.protocols.data.application.httpv1.HTTPv1
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.httpv1.Header
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.httpv1.RequestHeader
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.httpv1.ResponseHeader
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
