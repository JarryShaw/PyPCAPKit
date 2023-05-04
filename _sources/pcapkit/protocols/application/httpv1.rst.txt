HTTP/1.* - Hypertext Transfer Protocol
======================================

.. module:: pcapkit.protocols.application.httpv1

:mod:`pcapkit.protocols.application.httpv1` contains
:class:`~pcapkit.protocols.application.httpv1.HTTP`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/1.*) [*]_, whose structure is described
as below:

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

.. autoclass:: pcapkit.protocols.application.httpv1.HTTP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

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

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.application.httpv1

.. autoclass:: pcapkit.protocols.schema.application.httpv1.HTTP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.application.httpv1

.. autoclass:: pcapkit.protocols.data.application.httpv1.HTTP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.application.httpv1.Header
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.application.httpv1.RequestHeader
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.application.httpv1.ResponseHeader
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
