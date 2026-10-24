I/O Objects
===========

.. module:: pcapkit.corekit.io

:mod:`pcapkit.corekit.io` contains
:class:`~pcapkit.corekit.io.SeekableReader`, a seekable customisation of
:class:`io.BufferedReader`, and the stream proxies:
:class:`~pcapkit.corekit.io.PeekableStream`, which adds ``peek`` to a seekable
stream, and :class:`~pcapkit.corekit.io.NamedStream`, which gives a stream a
``name``; :func:`~pcapkit.corekit.io.advance`, which moves a stream past
more octets than one read or seek can take; and
:func:`~pcapkit.corekit.io.can_seek`, which tells whether a stream really seeks.

.. autoclass:: pcapkit.corekit.io.SeekableReader
   :no-members:
   :show-inheritance:

   .. autoproperty:: raw
   .. autoproperty:: closed

   .. autoattribute:: _stream
   .. autoattribute:: _closed

   .. automethod:: read
   .. automethod:: read1
   .. automethod:: readinto
   .. automethod:: readinto1
   .. automethod:: readable
   .. automethod:: readline
   .. automethod:: readlines

   .. automethod:: writable
   .. automethod:: write

   .. automethod:: seekable
   .. automethod:: seek
   .. automethod:: tell
   .. automethod:: truncate

   .. automethod:: close
   .. automethod:: flush

   .. automethod:: peek
   .. automethod:: detach

   .. automethod:: fileno
   .. automethod:: isatty

   .. autoattribute:: _read_ahead_size
   .. automethod:: _read_ahead
   .. automethod:: _truncate_buffer

.. autoclass:: pcapkit.corekit.io.PeekableStream
   :no-members:

   .. automethod:: peek

.. autoclass:: pcapkit.corekit.io.NamedStream
   :no-members:

   .. autoattribute:: name
   .. automethod:: read

.. autofunction:: pcapkit.corekit.io.advance
.. autofunction:: pcapkit.corekit.io.can_seek
