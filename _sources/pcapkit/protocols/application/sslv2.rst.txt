SSLv2 - Secure Sockets Layer version 2
=======================================

.. module:: pcapkit.protocols.application.sslv2

:mod:`pcapkit.protocols.application.sslv2` contains
:class:`~pcapkit.protocols.application.sslv2.SSLv2` only,
which implements an extractor for Secure Sockets Layer
version 2 (SSLv2) [*]_, whose record header is 2 or 3 octets, chosen by the
high bit of its first octet (``sslv2.indicator``):

.. code-block:: text

   2-octet form (high bit set):

      0                   1                   2
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |1|      sslv2.indicator/length_low (15)    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |sslv2.msg_type |   handshake message body ...

   3-octet form (high bit clear):

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |0|E|   sslv2.indicator/length_low (14)  |  sslv2.padding (8)   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |sslv2.msg_type |   handshake message body ...

``E`` is the ``IS-ESCAPE`` flag, meaningful only in the 3-octet form. See
:func:`~pcapkit.protocols.schema.application.sslv2.sslv2_record_length` for the
exact bit arithmetic.

SSLv2 is wire-*incompatible* with SSLv3 and TLS: it carries no content-type
byte and no ``0x03xx``-style record version, and its handshake message type
is the first octet of the record's data rather than a separate record-layer
field. This package parses the ``CLIENT-HELLO`` and ``SERVER-HELLO``
handshake message bodies; every other
:class:`~pcapkit.const.sslv2.handshake_type.HandshakeType`, and a hello-tagged
body whose declared sub-field lengths do not fit the record (e.g.
ciphertext), is kept as raw octets, header and message type decoded.

Records in One Segment
----------------------

A whole record after the first in a TCP segment is dissected as a further
:class:`~pcapkit.protocols.application.sslv2.SSLv2` layer, the previous record's
payload, whatever its message type (:issue:`2567`): a ``CLIENT-HELLO`` followed by
a ``CLIENT-MASTER-KEY`` reads ``SSLv2:SSLv2``. The exceptions:

* A whole record that fails to decode -- a ``RECORD-LENGTH`` of ``0``, which
  leaves no ``MSG-TYPE`` -- becomes :class:`~pcapkit.protocols.misc.raw.Raw`
  together with everything after it.
* Octets that open no record -- a header cut short, or a record the segment
  ends inside -- stay raw, with no error.
* A parse told to stop at SSLv2 (``protocol='SSLv2'`` or ``layer='Application'``)
  keeps the rest of the segment raw.
* Each record is a layer, so :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
  bounds how many are dissected.

.. versionadded:: 1.6.0

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.sslv2.SSLv2
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: id

   .. automethod:: _make_data
   .. automethod:: _make_sslv2_client_hello
   .. automethod:: _make_sslv2_server_hello

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.application.sslv2

.. autoclass:: pcapkit.protocols.schema.application.sslv2.SSLv2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.application.sslv2.HandshakeBody
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.application.sslv2.UnknownHandshakeBody
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.application.sslv2.ClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.application.sslv2.ServerHello
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.application.sslv2.sslv2_record_length
.. autofunction:: pcapkit.protocols.schema.application.sslv2.sslv2_hello_probe_length
.. autofunction:: pcapkit.protocols.schema.application.sslv2.sslv2_hello_probe_is_plausible
.. autofunction:: pcapkit.protocols.schema.application.sslv2.sslv2_body_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.application.sslv2

.. autoclass:: pcapkit.protocols.data.application.sslv2.SSLv2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.sslv2.ClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.sslv2.ServerHello
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
