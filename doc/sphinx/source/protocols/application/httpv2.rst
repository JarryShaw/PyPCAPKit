HTTP/2 - Hypertext Transfer Protocol
====================================

.. module:: pcapkit.protocols.application.httpv2

:mod:`pcapkit.protocols.application.httpv2` contains
:class:`~pcapkit.protocols.application.httpv2.HTTPv2`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/2) [*]_, whose structure is described as
below:

======= ========= ===================== ==========================
Octets      Bits        Name                    Description
======= ========= ===================== ==========================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.payload``            Frame Payload
======= ========= ===================== ==========================

.. raw:: html

   <br />

.. .. autoclass:: pcapkit.protocols.application.httpv2.HTTPv2
..    :members:
..    :undoc-members:
..    :private-members:
..    :show-inheritance:

.. data:: pcapkit.protocols.application.httpv2._HTTP_FUNC
   :type: Dict[int, Callable[[pcapkit.protocols.application.httpv2.HTTPv2, int, int, str], DataType_HTTPv2_Frame]]

   Process method for HTTP/2 packets.

   .. list-table::
      :header-rows: 1

      * - Code
        - Method
        - Description
      * - N/A
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_none`
        - Unsigned
      * - 0x00
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_data`
        - ``DATA``
      * - 0x01
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_headers`
        - ``HEADERS``
      * - 0x02
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_priority`
        - ``PRIORITY``
      * - 0x03
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_rst_stream`
        - ``RST_STREAM``
      * - 0x04
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_settings`
        - ``SETTINGS``
      * - 0x05
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_push_promise`
        - ``PUSH_PROMISE``
      * - 0x06
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_ping`
        - ``PING``
      * - 0x07
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_goaway`
        - ``GOAWAY``
      * - 0x08
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_window_update`
        - ``WINDOW_UPDATE``
      * - 0x09
        - :meth:`~pcapkit.protocols.application.httpv2.HTTPv2._read_http_continuation`
        - ``CONTINUATION``

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_HTTPv2

   :bases: TypedDict

   Structure of HTTP/2 packet [:rfc:`7540`].

   .. attribute:: length
      :type: int

      Length.

   .. attribute:: type
      :type: pcapkit.const.http.frame.Frame

      Type.

   .. attribute:: sid
      :type: int

      Stream identifier.

   .. attribute:: packet
      :type: bytes

      Raw packet data.

.. class:: DataType_HTTPv2_Frame

   :bases: TypedDict

   HTTP/2 packet data.

HTTP/2 Unassigned Frame
~~~~~~~~~~~~~~~~~~~~~~~

.. class:: DataType_HTTPv2_Unassigned

   :bases: DataType_HTTPv2_Frame

   .. attribute:: flags
      :type: Literal[None]

      HTTP/2 packet flags.

   .. attribute:: payload
      :type: Optional[types]

      Raw packet payload.

HTTP/2 ``DATA`` Frame
~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``DATA`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ===================== ==========================
Octets      Bits        Name                    Description
======= ========= ===================== ==========================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``0``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.pad_len``            Pad Length (Optional)
  10         80   ``http.data``               Data
  ?           ?                               Padding (Optional)
======= ========= ===================== ==========================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_DATA

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``DATA`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: DataType_HTTPv2_DATA_Flags

      HTTP/2 packet flags.

   .. attribute:: data
      :type: bytes

      HTTP/2 transferred data.

.. class:: DataType_HTTPv2_DATA_Flags

   :bases: TypedDict

   HTTP/2 ``DATA`` frame packet flags.

   .. attribute:: END_STREAM
      :type: bool

      [BIT 0] End of stream flag.

   .. attribute:: PADDED
      :type: bool

      [BIT 3] Padded flag.



.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/HTTP/2
