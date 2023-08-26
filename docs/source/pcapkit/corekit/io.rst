Seekable I/O Object
===================

.. module:: pcapkit.corekit.io

:mod:`pcapkit.corekit.io` contains seekable I/O object
:class:`~pcapkit.corekit.io.SeekableReader`, which is a customised
implementation to :class:`io.BufferedReader`.

.. autoclass:: pcapkit.corekit.io.SeekableReader
   :no-members:
   :show-inheritance:

   .. autoproperty:: raw
   .. autoproperty:: closed

   .. automethod:: read
   .. automethod:: read1
   .. automethod:: readinto
   .. automethod:: readinto1
   .. automethod:: readable
   .. automethod:: readline
   .. automethod:: readlines

   .. automethod:: writeable
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
