Text Protocol Lines
===================

.. module:: pcapkit.utilities.lines

:mod:`pcapkit.utilities.lines` reads and writes what the line-based text
protocols exchange: CRLF-terminated lines, a reply that runs over several lines,
a block of dot-stuffed lines ended by a line holding a single period, and the
text a line carries. FTP and SMTP share it, so it lives beside neither
(:ref:`utilities-or-corekit`).

.. versionadded:: 1.10.0

.. autofunction:: pcapkit.utilities.lines.split_lines
.. autofunction:: pcapkit.utilities.lines.join_lines
.. autofunction:: pcapkit.utilities.lines.closes_reply
.. autofunction:: pcapkit.utilities.lines.block_end
.. autofunction:: pcapkit.utilities.lines.stuff
.. autofunction:: pcapkit.utilities.lines.unstuff
.. autofunction:: pcapkit.utilities.lines.decode_text
