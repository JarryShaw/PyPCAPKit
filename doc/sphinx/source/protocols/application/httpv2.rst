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

.. autoclass:: pcapkit.protocols.application.httpv2.HTTPv2
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

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

      :bit: 0

   .. attribute:: PADDED
      :type: bool

      :bit: 3

HTTP/2 ``HEADERS`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``HEADERS`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ===================== ====================================
Octets      Bits        Name                    Description
======= ========= ===================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``1``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.pad_len``            Pad Length (Optional)
  10         80   ``http.exclusive``          Exclusive Flag
  10         81   ``http.deps``               Stream Dependency (Optional)
  14        112   ``http.weight``             Weight (Optional)
  15        120   ``http.frag``               Header Block Fragment
  ?           ?                               Padding (Optional)
======= ========= ===================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_HEADERS

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``HEADERS`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: DataType_HTTPv2_HEADERS_Flags

      HTTP/2 packet flags.

   .. attribute:: frag
      :type: Optional[bytes]

      Header block fragment.

   .. attribute:: pad_len
      :type: int

      Pad length.

   .. attribute:: exclusive
      :type: bool

      Exclusive flag.

   .. attribute:: deps
      :type: int

      Stream dependency.

   .. attribute:: weight
      :type: int

      Weight.

.. class:: DataType_HTTPv2_HEADERS_Flags

   :bases: TypedDict

   HTTP/2 ``HEADERS`` frame packet flags.

   .. attribute:: END_STREAM
      :type: bool

      :bit: 0

   .. attribute:: END_HEADERS
      :type: bool

      :bit: 2

   .. attribute:: PADDED
      :type: bool

      :bit: 3

   .. attribute:: PRIORITY
      :type: bool

      :bit: 5

HTTP/2 ``PRIORITY`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``PRIORITY`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ===================== ====================================
Octets      Bits        Name                    Description
======= ========= ===================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``2``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.exclusive``          Exclusive Flag
  9          73   ``http.deps``               Stream Dependency
  13        104   ``http.weight``             Weight
======= ========= ===================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_PRIORITY

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``PRIORITY`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: Literal[None]

      HTTP/2 packet flags.

   .. attribute:: exclusive
      :type: bool

      Exclusive flag.

   .. attribute:: deps
      :type: int

      Stream dependency.

   .. attribute:: weight
      :type: int

      Weight.

HTTP/2 ``RST_STREAM`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``RST_STREAM`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ===================== ====================================
Octets      Bits        Name                    Description
======= ========= ===================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``3``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.error``              Error Code
======= ========= ===================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_RST_STREAM

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``PRIORITY`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: Literal[None]

      HTTP/2 packet flags.

   .. attribute:: error
      :type: pcapkit.const.http.error_code.ErrorCode

      Error code.

HTTP/2 ``SETTINGS`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``SETTINGS`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ======================== ====================================
Octets      Bits        Name                    Description
======= ========= ======================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``4``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.settings``           Settings
  9          72   ``http.settings.id``        Identifier
  10         80   ``http.settings.value``     Value
======= ========= ======================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_SETTINGS

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``SETTINGS`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: DataType_HTTPv2_SETTINGS_Flags

      HTTP/2 packet flags.

   .. attribute:: settings
      :type: Tuple[pcapkit.const.http.setting.Setting]

      Array of HTTP/2 settings.

.. class:: DataType_HTTPv2_SETTINGS_Flags

   :bases: TypedDict

   HTTP/2 packet flags.

   .. attribute:: ACK
      :type: bool

      :bit: 0

HTTP/2 ``PUSH_PROMISE`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``PUSH_PROMISE`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ======================== ====================================
Octets      Bits        Name                    Description
======= ========= ======================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``5``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.pad_len``            Pad Length (Optional)
  10         80                               Reserved
  10         81   ``http.pid``                Promised Stream ID
  14        112   ``http.frag``               Header Block Fragment
  ?           ?                               Padding (Optional)
======= ========= ======================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_PUSH_PROMISE

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``PUSH_PROMISE`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: DataType_HTTPv2_PUSH_PROMISE_Flags

      HTTP/2 packet flags.

   .. attribute:: pid
      :type: int

      Promised stream ID.

   .. attribute:: frag
      :type: Optional[bytes]

      Header block fragment.

   .. attribute:: pad_len
      :type: int

      Pad length.

.. class:: DataType_HTTPv2_PUSH_PROMISE_Flags

   :bases: TypedDict

   HTTP/2 packet flags.

   .. attribute:: END_HEADERS
      :type: bool

      :bit: 2

   .. attribute:: PADDED
      :type: bool

      :bit: 3

HTTP/2 ``PING`` Frame
~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``PING`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ======================== ====================================
Octets      Bits        Name                    Description
======= ========= ======================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``6``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.data``               Opaque Data
======= ========= ======================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_PING

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``PING`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: DataType_HTTPv2_PING_Flags

      HTTP/2 packet flags.

   .. attribute:: data
      :type: bytes

      Opaque data.

.. class:: DataType_HTTPv2_PING_Flags

   :bases: TypedDict

   HTTP/2 packet flags.

   .. attribute:: ACK
      :type: bool

      :bit: 0

HTTP/2 ``GOAWAY`` Frame
~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``GOAWAY`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ======================== ====================================
Octets      Bits        Name                    Description
======= ========= ======================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``7``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72                               Reserved
  9          73   ``http.last_sid``           Last Stream ID
  13        104   ``http.error``              Error Code
  17        136   ``http.data``               Additional Debug Data (Optional)
======= ========= ======================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_GOAWAY

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``GOAWAY`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: Literal[None]

      HTTP/2 packet flags.

   .. attribute:: last_sid
      :type: int

      Last stream ID.

   .. attribute:: error
      :type: pcapkit.const.http.error_code.ErrorCode

      Error code.

   .. attribute:: data
      :type: Optional[None]

      Additional debug data.

HTTP/2 ``WINDOW_UPDATE`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``WINDOW_UPDATE`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ======================== ====================================
Octets      Bits        Name                    Description
======= ========= ======================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``8``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72                               Reserved
  9          73   ``http.window``             Window Size Increment
======= ========= ======================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_WINDOW_UPDATE

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``WINDOW_UPDATE`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: Literal[None]

      HTTP/2 packet flags.

   .. attribute:: window
      :type: int

      Window size increment.

HTTP/2 ``CONTINUATION`` Frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HTTP/2 ``CONTINUATION`` frame as described in :rfc:`7540`,
its structure is described as below:

======= ========= ======================== ====================================
Octets      Bits        Name                    Description
======= ========= ======================== ====================================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type (``9``)
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          73   ``http.frag``               Header Block Fragment
======= ========= ======================== ====================================

.. raw:: html

   <br />

.. class:: DataType_HTTPv2_CONTINUATION

   :bases: DataType_HTTPv2_Frame

   Structure of HTTP/2 ``CONTINUATION`` frame [:rfc:`7540`].

   .. attribute:: flags
      :type: DataType_HTTPv2_CONTINUATION_Flags

      HTTP/2 packet flags.

   .. attribute:: frag
      :type: bytes

      Header block fragment.

.. class:: DataType_HTTPv2_CONTINUATION_Flags

   :bases: TypedDict

   HTTP/2 packet flags.

   .. attribute:: END_HEADERS
      :type: bool

      :bit: 2

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/HTTP/2
