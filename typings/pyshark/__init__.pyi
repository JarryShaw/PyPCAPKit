"""Type stubs for the part of ``pyshark`` that :mod:`pcapkit` uses (#1878).

Written against pyshark 0.6, from its source as installed; pyshark ships no
type information of its own. Only the names :mod:`pcapkit` reads are declared,
so this is not a general-purpose stub: declare a name here before
:mod:`pcapkit` starts to use it.

:file:`mypy.ini` registers this directory through ``mypy_path``. It is not part
of the wheel or the sdist.

"""
from pyshark.capture.file_capture import FileCapture as FileCapture
