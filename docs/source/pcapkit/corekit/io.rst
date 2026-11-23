I/O Objects
===========

.. module:: pcapkit.corekit.io

:mod:`pcapkit.corekit.io` contains:

* :class:`~pcapkit.corekit.io.SeekableReader`, a seekable customisation of
  :class:`io.BufferedReader`;
* the stream proxies :class:`~pcapkit.corekit.io.PeekableStream`, which adds
  ``peek`` to a seekable stream, and :class:`~pcapkit.corekit.io.NamedStream`,
  which gives a stream a ``name``;
* :func:`~pcapkit.corekit.io.advance`, which moves a stream past more octets
  than one read or seek can take;
* :func:`~pcapkit.corekit.io.can_seek`, which tells whether a stream really
  seeks.

.. autoclass:: pcapkit.corekit.io.SeekableReader
   :no-members:
   :show-inheritance:

   .. autoattribute:: _closed
   .. autoattribute:: _stream
   .. autoattribute:: _read_ahead_size

   .. autoproperty:: closed
   .. autoproperty:: raw

   .. automethod:: _read_ahead

   .. automethod:: close
   .. automethod:: fileno
   .. automethod:: flush
   .. automethod:: isatty
   .. automethod:: readable
   .. automethod:: readline
   .. automethod:: readlines
   .. automethod:: seek
   .. automethod:: seekable
   .. automethod:: tell
   .. automethod:: truncate

   .. automethod:: _truncate_buffer

   .. automethod:: writable
   .. automethod:: detach
   .. automethod:: read
   .. automethod:: read1
   .. automethod:: readinto
   .. automethod:: readinto1
   .. automethod:: write
   .. automethod:: peek

.. autoclass:: pcapkit.corekit.io.PeekableStream
   :no-members:

   .. automethod:: peek

.. autoclass:: pcapkit.corekit.io.NamedStream
   :no-members:

   .. automethod:: read
   .. autoattribute:: name

.. autofunction:: pcapkit.corekit.io.advance
.. autofunction:: pcapkit.corekit.io.can_seek
