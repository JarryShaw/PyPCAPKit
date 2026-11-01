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

:mod:`pcapkit.corekit` **is for the types the packet model is built from**: what
:mod:`pcapkit.protocols`, :mod:`pcapkit.const` and :mod:`pcapkit.foundation`
subclass, instantiate or decorate with. The question is *is this part of what a
protocol or its schema is made of?* A support module that fails the ``utilities``
question belongs here instead. :mod:`pcapkit.corekit.decorators` is the worked example: it acts on a
protocol's file and falls back to protocol classes, so it moved out of ``utilities``
on :issue:`1735`. ``corekit`` may import ``utilities``; the reverse is what the rule
forbids.

A second worked example is :mod:`pcapkit.corekit.checksum`, settled on :issue:`2580`.
It fails the ``utilities`` question because
:class:`~pcapkit.corekit.checksum.internet.ChecksumStatus` subclasses
:class:`~pcapkit.corekit.enum.EnumLookup`. The protocols compute and verify their
checksums through it, so it imports
:mod:`pcapkit` only from ``corekit`` and ``utilities``, never from
:mod:`pcapkit.protocols`; :file:`tests/corekit/test_checksum_import_boundary_2580_unit.py`
checks that. What needs IPv4 and IPv6 stays beside
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo`. The package holds one
module per checksum family, so a new family sits beside
:mod:`~pcapkit.corekit.checksum.internet`.
