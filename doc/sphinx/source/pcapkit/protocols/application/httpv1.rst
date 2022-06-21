HTTP/1.* - Hypertext Transfer Protocol
======================================

.. module:: pcapkit.protocols.application.httpv1
.. module:: pcapkit.protocols.data.application.httpv1

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

   .. automethod:: read
   .. automethod:: make
   .. automethod:: id

   .. automethod:: _read_http_header
   .. automethod:: _read_http_body

.. autodata:: pcapkit.protocols.application.httpv1.HTTP_METHODS

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.application.httpv1.HTTP(receipt, header, body)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: receipt
   .. autoattribute:: header
   .. autoattribute:: body

.. autoclass:: pcapkit.protocols.data.application.httpv1.Header(type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type

.. autoclass:: pcapkit.protocols.data.application.httpv1.RequestHeader(type, method, uri, version)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: method
   .. autoattribute:: uri
   .. autoattribute:: version

.. autoclass:: pcapkit.protocols.data.application.httpv1.ResponseHeader(type, version, status, message)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: version
   .. autoattribute:: status
   .. autoattribute:: message

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
