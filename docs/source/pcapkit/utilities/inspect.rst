Abstract Classes
================

.. module:: pcapkit.utilities.inspect

:mod:`pcapkit.utilities.inspect` holds :func:`isabstract`, which tells an abstract
class from a concrete one without the interpreter's abstract flag, so the answer is the
same on every interpreter, during :meth:`~object.__init_subclass__` and after the class
is made (:issue:`2784`). :meth:`Protocol.__init_subclass__
<pcapkit.protocols.protocol.Protocol.__init_subclass__>` decides with it whether a
class names itself in the by-name registry. It behaves the same everywhere rather
than gating on a version, so it is not in :mod:`~pcapkit.utilities.compat`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

.. autofunction:: pcapkit.utilities.inspect.isabstract
