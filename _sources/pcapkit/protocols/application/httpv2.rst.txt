HTTP/2 - Hypertext Transfer Protocol
====================================

.. module:: pcapkit.protocols.application.httpv2
.. module:: pcapkit.protocols.application.httpv2.protocol

:mod:`pcapkit.protocols.application.httpv2.protocol` contains
:class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`
only, which implements an extractor for Hypertext Transfer
Protocol (HTTP/2) [*]_, whose structure is described as
below:

======= ========= ===================== ==========================
Octets      Bits        Name                    Description
======= ========= ===================== ==========================
  0           0   ``http.length``             Payload Length
  3          24   ``http.type``               Type
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.payload``            Frame Payload
======= ========= ===================== ==========================

Frames in One Segment
---------------------

A whole frame after the first in a TCP segment is dissected as a further
:class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2` layer, the previous
frame's payload (:issue:`2536`), as
:class:`~pcapkit.protocols.application.tls.protocol.TLS` chains records: a ``SETTINGS``
frame followed by a ``WINDOW_UPDATE`` reads ``TCP:HTTP/2:HTTP/2``. The
exceptions:

* A whole frame that fails to decode becomes
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw` together with everything after it,
  with the parser's ``error``.
* A frame the segment ends inside, its header or its payload cut short, stays
  raw, with no error.
* A parse told to stop at HTTP/2 (``protocol='HTTP/2'`` or
  ``layer='Application'``) keeps the rest of the segment raw.
* Each frame is a layer, so :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
  bounds how many are dissected.

.. versionchanged:: 1.5.0

   A frame's Length counts its payload alone, not the 9-octet frame header,
   as :rfc:`9113#section-4.1` defines it, and the payload is read to that
   Length rather than to the end of the buffer (:issue:`1121`,
   :issue:`1243`). A frame rebuilds byte for byte: ``END_STREAM``, undefined
   flag bits, the reserved bits, a zero Pad Length, duplicate SETTINGS
   entries and the payload of an unpadded DATA, HEADERS or PUSH_PROMISE frame
   are kept (:issue:`652`, :issue:`668`, :issue:`1244`, :issue:`1245`,
   :issue:`1246`, :issue:`1247`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.application.httpv2.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`,
   after its module (:issue:`2529`).

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.httpv2.protocol.HTTPv2
   :no-members:
   :show-inheritance:

   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: version

   .. automethod:: id
   .. automethod:: register_frame

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _read_http_none
   .. automethod:: _read_http_data
   .. automethod:: _read_http_headers
   .. automethod:: _read_http_priority
   .. automethod:: _read_http_rst_stream
   .. automethod:: _read_http_settings
   .. automethod:: _read_http_push_promise
   .. automethod:: _read_http_ping
   .. automethod:: _read_http_goaway
   .. automethod:: _read_http_window_update
   .. automethod:: _read_http_continuation

   .. automethod:: _make_http_none
   .. automethod:: _make_http_data
   .. automethod:: _make_http_headers
   .. automethod:: _make_http_priority
   .. automethod:: _make_http_rst_stream
   .. automethod:: _make_http_settings
   .. automethod:: _make_http_push_promise
   .. automethod:: _make_http_ping
   .. automethod:: _make_http_goaway
   .. automethod:: _make_http_window_update
   .. automethod:: _make_http_continuation

   .. autoattribute:: __frame__
      :no-value:

   .. automethod:: unpack

Header Schemas
--------------

.. module:: pcapkit.protocols.application.httpv2.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.httpv2``, with no alias: the module moved here
   (:issue:`2534`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.httpv2.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.application.httpv2.schema.HTTPv2`,
   after its module (:issue:`2529`).

.. autoclass:: pcapkit.protocols.application.httpv2.schema.HTTPv2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.FrameType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.UnassignedFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.DataFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.HeadersFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.PriorityFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.RSTStreamFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.SettingPair
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.SettingsFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.PushPromiseFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.PingFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.GoawayFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.WindowUpdateFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.ContinuationFrame
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.application.httpv2.schema.FrameFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.StreamID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.StreamDependency
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.schema.WindowSize
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.httpv2.schema.http_frame_selector

Data Models
-----------

.. module:: pcapkit.protocols.application.httpv2.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.application.httpv2``, with no alias: the module moved here
   (:issue:`2534`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.application.httpv2.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.application.httpv2.data.HTTPv2`,
   after its module (:issue:`2529`).

.. autoclass:: pcapkit.protocols.application.httpv2.data.HTTPv2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.UnassignedFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.DataFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.DataFrameFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.HeadersFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.HeadersFrameFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.PriorityFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.RSTStreamFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.SettingsFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.Settings
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.SettingsFrameFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.PushPromiseFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.PushPromiseFrameFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.PingFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.PingFrameFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.GoawayFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.WindowUpdateFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.ContinuationFrame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.httpv2.data.ContinuationFrameFlags
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/HTTP/2
