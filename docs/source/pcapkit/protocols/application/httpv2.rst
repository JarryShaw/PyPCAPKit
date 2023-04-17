HTTP/2 - Hypertext Transfer Protocol
====================================

.. module:: pcapkit.protocols.application.httpv2
.. module:: pcapkit.protocols.data.application.httpv2

:mod:`pcapkit.protocols.application.httpv2` contains
:class:`~pcapkit.protocols.application.httpv2.HTTP`
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

.. autoclass:: pcapkit.protocols.application.httpv2.HTTP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: version

   .. automethod:: read
   .. automethod:: make
   .. automethod:: id
   .. automethod:: register_frame

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

   .. autoattribute:: __frame__
      :no-value:

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.application.httpv2.HTTP(length, type, flags, sid)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: length
   .. autoattribute:: type
   .. autoattribute:: flags
   .. autoattribute:: sid

.. autoclass:: pcapkit.protocols.data.application.httpv2.Flags()
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.application.httpv2.UnassignedFrame(length, type, flags, sid, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.application.httpv2.DataFrame(length, type, flags, sid, pad_len, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: pad_len
   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.application.httpv2.DataFrameFlags(END_STREAM, PADDED)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: END_STREAM
   .. autoattribute:: PADDED

.. autoclass:: pcapkit.protocols.data.application.httpv2.HeadersFrame(length, type, flags, sid, pad_len, excl_dependency, stream_dependency, weight, fragment)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: pad_len
   .. autoattribute:: excl_dependency
   .. autoattribute:: stream_dependency
   .. autoattribute:: weight
   .. autoattribute:: fragment

.. autoclass:: pcapkit.protocols.data.application.httpv2.HeadersFrameFlags(END_STREAM, END_HEADERS, PADDED, PRIORITY)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: END_STREAM
   .. autoattribute:: END_HEADERS
   .. autoattribute:: PADDED
   .. autoattribute:: PRIORITY

.. autoclass:: pcapkit.protocols.data.application.httpv2.PriorityFrame(length, type, flags, sid, excl_dependency, stream_dependency, weight)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: excl_dependency
   .. autoattribute:: stream_dependency
   .. autoattribute:: weight

.. autoclass:: pcapkit.protocols.data.application.httpv2.RSTStreamFrame(length, type, flags, sid, error)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: error

.. autoclass:: pcapkit.protocols.data.application.httpv2.SettingsFrame(length, type, flags, sid, settings)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: settings

.. autoclass:: pcapkit.protocols.data.application.httpv2.SettingsFrameFlags(ACK)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ACK

.. autoclass:: pcapkit.protocols.data.application.httpv2.PushPromiseFrame(length, type, flags, sid, pad_len, promised_sid, fragment)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: pad_len
   .. autoattribute:: promised_sid
   .. autoattribute:: fragment

.. autoclass:: pcapkit.protocols.data.application.httpv2.PushPromiseFrameFlags(END_HEADERS, PADDED)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: END_HEADERS
   .. autoattribute:: PADDED

.. autoclass:: pcapkit.protocols.data.application.httpv2.PingFrame(length, type, flags, sid, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.application.httpv2.PingFrameFlags(ACK)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ACK

.. autoclass:: pcapkit.protocols.data.application.httpv2.GoawayFrame(length, type, flags, sid, last_sid, error, debug_data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: last_sid
   .. autoattribute:: error
   .. autoattribute:: debug_data

.. autoclass:: pcapkit.protocols.data.application.httpv2.WindowUpdateFrame(length, type, flags, sid, increment)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: increment

.. autoclass:: pcapkit.protocols.data.application.httpv2.ContinuationFrame(length, type, flags, sid, fragment)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: fragment

.. autoclass:: pcapkit.protocols.data.application.httpv2.ContinuationFrameFlags(END_HEADERS)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: END_HEADERS

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/HTTP/2
