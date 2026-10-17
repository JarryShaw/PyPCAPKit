"""Type stubs for the part of ``pcapfile`` that :mod:`pcapkit` uses (#1878).

Written against pypcapfile 0.12.0, from the source it publishes on PyPI; it
ships no type information of its own. Only the names :mod:`pcapkit` reads are
declared, so this is not a general-purpose stub: declare a name here before
:mod:`pcapkit` starts to use it.

The package itself imports none of the submodules below; each is an attribute
of it once imported. They are declared here because
:class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` imports all of them
before it reads one through the package, and mypy matches a module against a
:class:`~typing.Protocol` by what its stub declares.

:file:`mypy.ini` registers this directory through ``mypy_path``. It is not part
of the wheel or the sdist.

"""
from . import linklayer as linklayer
from . import savefile as savefile
from . import structs as structs
