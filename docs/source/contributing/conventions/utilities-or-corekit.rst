.. _utilities-or-corekit:

Choosing Between ``utilities`` and ``corekit``
----------------------------------------------

Which of the two support packages a module belongs in. Settled by the owner on
:issue:`1712`, over alternatives that sorted modules by packet knowledge or by
who uses them. This rule can be checked from the import graph alone, and it needed
the fewest moves: one.

:mod:`pcapkit.utilities` **is for cross-cutting services**: exceptions, warnings,
logging, the compatibility layer, configuration, and wrappers around third-party
libraries such as :mod:`~pcapkit.utilities.chardet`. The question to ask of a module
is *could any code use this service, and does it import nothing from* :mod:`pcapkit`
*outside* ``utilities``? Both halves have to hold, and *nothing* covers a top-level
import, one inside a function and one under ``TYPE_CHECKING`` alike.
:file:`tests/project/test_utilities_import_boundary_1735_unit.py` checks every module
under :file:`pcapkit/utilities/` for it.

:mod:`pcapkit.utilities.compat` **holds compatibility implementations and re-exports
only.** Where a name or behaviour differs by interpreter version, ``compat`` re-exports
the right one behind a :data:`sys.version_info` gate rather than a ``getattr`` or
``hasattr`` probe. That was ruled in review of the threading excepthook and
``AppType`` union fixes for :issue:`1691` and :issue:`1694`, neither of whose threads
holds it, and applied to the package's other probes on :issue:`1709`.
:file:`tests/project/test_stdlib_feature_probes_1709_unit.py` fails on a ``getattr``
or ``hasattr`` call naming its attribute in a string literal, where the receiver is a
builtin class or a module the file binds with an ``import`` statement, or where the
attribute is one the test lists with the interpreter version that added it; the calls
it exempts pass. A helper that has to behave the same on every platform is
neither a compatibility implementation nor a re-export, so it gets a module of its
own: that is why :func:`~pcapkit.utilities.datetime.fromtimestamp` is in
:mod:`pcapkit.utilities.datetime`, ruled in review of the timestamp fix for
:issue:`2099`, whose thread does not hold it.

:mod:`pcapkit.corekit` **is for the types the packet model is built from**: what
:mod:`pcapkit.protocols`, :mod:`pcapkit.const` and :mod:`pcapkit.foundation`
subclass, instantiate or decorate with. The question is *is this part of what a
protocol or its schema is made of?* A support module that fails the ``utilities``
question belongs here instead. :mod:`pcapkit.corekit.decorators` is the worked example: it acts on a
protocol's file and falls back to protocol classes, so it moved out of ``utilities``
on :issue:`1735`. ``corekit`` may import ``utilities``; the reverse is what the rule
forbids.
