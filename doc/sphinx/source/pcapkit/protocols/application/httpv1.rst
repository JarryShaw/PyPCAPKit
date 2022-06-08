HTTP/1.* - Hypertext Transfer Protocol
======================================

:mod:`pcapkit.protocols.application.httpv1` contains
:class:`~pcapkit.protocols.application.httpv1.HTTPv1`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/1.*) [*]_, whose structure is described
as below::

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

.. automodule:: pcapkit.protocols.application.httpv1
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_HTTP

   :bases: TypedDict

   Structure of HTTP/1.* packet [:rfc:`7230`].

   .. attribute:: receipt
      :type: Literal['request', 'response']

      HTTP packet receipt.

   .. attribute:: header
      :type: Union[DataType_HTTP_Request_Header, DataType_HTTP_Response_Header]

      Parsed HTTP header data.

   .. attribute:: body
      :type: bytes

      HTTP body data.

   .. attribute:: raw
      :type: DataType_HTTP_Raw

      Raw HTTP packet data.

.. class:: DataType_HTTP_Raw

   :bases: TypedDict

   Raw HTTP packet data.

   .. attribute:: header
      :type: bytes

      Raw HTTP header data.

   .. attribute:: body
      :type: bytes

      Raw HTTP body data.

   .. attribute:: packet
      :type: bytes

      Raw HTTP packet data.

.. class:: DataType_HTTP_Request_Header

   :bases: TypedDict

   HTTP request header.

   .. attribute:: request
      :type: DataType_HTTP_Request_Header_Meta

      Request metadata.

.. class:: DataType_HTTP_Response_Header

   :bases: TypedDict

   HTTP response header.

   .. attribute:: response
      :type: DataType_HTTP_Response_Header_Meta

      Response metadata.

.. class:: DataType_HTTP_Request_Header_Meta

   :bases: TypedDict

   Request metadata.

   .. attribute:: method
      :type: str

      HTTP request method.

   .. attribute:: target
      :type: str

      HTTP request target URI.

   .. attribute:: version
      :type: Literal['0.9', '1.0', '1.1']

      HTTP version string.

.. class:: DataType_HTTP_Response_Header_Meta

   :bases: TypedDict

   Response metadata.

   .. attribute:: version
      :type: Literal['0.9', '1.0', '1.1']

      HTTP version string.

   .. attribute:: status
      :type: int

      HTTP response status code.

   .. attribute:: phrase
      :type: str

      HTTP response status reason.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
