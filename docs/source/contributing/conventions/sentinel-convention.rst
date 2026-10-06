.. _sentinel-convention:

Naming a Sentinel
-----------------

A *sentinel* here is a module-level singleton whose only job is to be recognised by
identity -- ``value is SENTINEL`` -- so that it can never be confused with a value a
caller might legitimately pass. The house rule, from the maintainer, covers the type:
the sentinel object's type class is named ``<SENTINEL>Type``.

That is, the class takes the instance's name in CamelCase with ``Type`` appended. It
says nothing about the **object**'s own name, which is what let three casings diverge
with no rule naming any of them wrong. GitHub issue :issue:`937` closed that gap: the
owner ruled for SCREAMING_SNAKE and accepted the resulting breaking change outright, with
no backport. So the object is named in SCREAMING_SNAKE and the type-naming rule above
derives from it mechanically -- title-case each underscore-separated word and append
``Type``, no per-sentinel exception needed. The four in the tree follow it:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Instance
     - Type
     - Defined in
   * - ``NULL``
     - ``NullType``
     - :mod:`pcapkit.corekit.sentinels`
   * - ``NO_VALUE``
     - ``NoValueType``
     - :mod:`pcapkit.corekit.sentinels`
   * - ``NO_DEFAULT``
     - ``NoDefaultType``
     - :mod:`pcapkit.corekit.sentinels`
   * - ``ABSENT``
     - ``AbsentType``
     - :mod:`pcapkit.corekit.sentinels`

GitHub issue :issue:`911`'s housing ruling -- one module for all four -- is why the table
names a single defining module. Each of the four modules that *uses* a sentinel keeps a
re-export of it, so ``from <module> import <name>`` keeps working for
:mod:`pcapkit.corekit.module`, :mod:`pcapkit.corekit.fields.field`,
:mod:`pcapkit.corekit.enum` and :mod:`pcapkit.protocols.protocol` alike, including a
caller's ``if TYPE_CHECKING:``-only import of the type.

Where a sentinel name already exists and already follows SCREAMING_SNAKE, keep it;
renaming a published sentinel again costs every caller for no further gain.

``ABSENT`` carries no leading underscore even though it is private -- it is read in
``_declared_keywords`` and discarded there, never leaving
:mod:`pcapkit.protocols.protocol`. The owner ruled on :issue:`937` that dropping the
underscore is fine so long as the documentation states that the type and the object are
private and not for public use, which is what this page and
:class:`~pcapkit.corekit.sentinels.AbsentType`'s own docstring do in its place. So
**privacy here is documentation-only**, and nothing in the name marks it out: when
adding a sentinel, add it to the table above whether or not it is public.

What reaches users is the **object only**. The owner ruled on GitHub issue :issue:`911`
that the objects alone -- ``NULL`` and its siblings -- are exported to users, so a public
sentinel names its instance in its module's ``__all__`` and leaves the type out of it.
The type stays importable by its dotted path, for an annotation or an ``is`` guard; it
is only ``import *`` that does not offer it. A private sentinel such as ``ABSENT`` is in
neither, which is what private means here -- dropping its leading underscore did not
add it to either list, and :class:`~pcapkit.corekit.sentinels.AbsentType` and
:data:`~pcapkit.corekit.sentinels.ABSENT` are documented on
:doc:`the sentinels API page </pcapkit/corekit/sentinels>` as private and not for
public use rather than left off it, since the name alone no longer says so.

.. note::

   Of the four, only :class:`~pcapkit.corekit.sentinels.NullType` is a full worked
   example. :class:`~pcapkit.corekit.sentinels.NoValueType` follows the naming rule but
   is **not** a singleton (``NoValueType() is NO_VALUE`` is :obj:`False`) and has no
   ``__repr__`` of its own, so it demonstrates the name and nothing else; ``AbsentType``
   has a ``__repr__`` (``<absent>``) but no singleton guard either. Copy ``NullType``
   when you need a pattern to follow.

Why a Class and Not ``object()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A bare ``object()`` is just as safe under ``is``, so safety is not the reason. The
reason is legibility: a dedicated class can define ``__repr__``, and that repr is what
appears in a signature, in :func:`help` output and in a traceback. Compare what
:func:`inspect.signature` renders for a method whose default is the sentinel:

.. code-block:: text

   # bare object(): an address, different every process
   default: 'Any' = <object object at 0x7fc393324cf0>

   # dedicated type with __repr__
   default: 'Any' = <NO_DEFAULT>

.. warning::

   Do **not** justify a dedicated class by claiming a subclass "could still compare
   equal via a custom ``__eq__``". A class that defines only ``__repr__`` inherits
   identity ``__eq__`` and is exactly as safe as ``object()``. That argument appeared
   in an early draft of :mod:`pcapkit.corekit.enum` and was wrong.

**Ported code is exempt.** ``_NOT_FOUND = object()`` at
:file:`pcapkit/utilities/compat.py`, line 73, sits inside the ``cached_property``
backport taken for interpreters below 3.8, which tracks CPython's own
:mod:`functools` implementation down to that name. It is **not** to be converted: the
value of a vendored backport is that it can still be diffed against upstream, and a
house-style rewrite destroys that in exchange for a sentinel nobody outside the backport
ever sees. The rule above is for sentinels this package writes itself.

Per-Sentinel Dunder Methods
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The four sentinels deliberately differ, and the differences are **needs, not
inconsistencies**:

``__new__`` returning a cached instance
   Guards against a caller constructing a second, non-identical sentinel that then
   fails every ``is`` check. Worth having wherever the type is reachable by a caller at
   all -- which, since the type is kept out of ``__all__``, means wherever it is
   importable by its dotted path rather than wherever it is star-exported.
   :class:`~pcapkit.corekit.sentinels.NullType` documents the limit honestly: a module
   **reload** re-executes the class statement, so the guard does not survive one, and
   code holding the pre-reload instance will fail ``is``. The module that matters there
   is :mod:`pcapkit.corekit.sentinels`, where the class statement lives; reloading one
   of the re-exporting modules has no effect on the sentinel.

``__bool__`` returning :obj:`False`
   ``NULL``, ``NO_VALUE`` and ``ABSENT`` have it, because each stands for an *absent
   value* and reads naturally in a boolean test. ``NO_DEFAULT`` deliberately does
   **not**: it is a marker meaning *no default was supplied*, it is only ever tested
   with ``is``, and making it falsy would invite ``if not default:`` -- which would
   then treat a caller's genuine falsy default (``0``, ``''``, :obj:`None`,
   :obj:`False`) the same as the sentinel, the very confusion the sentinel exists to
   prevent.

``__copy__`` / ``__deepcopy__`` / ``__reduce__``
   :class:`~pcapkit.corekit.sentinels.NullType` is the only one of the four that has
   them, because ``NULL`` is stored in a
   :class:`~pcapkit.corekit.module.ModuleDescriptor` field, so a caller's
   :func:`copy.deepcopy` or :mod:`pickle` can walk into it and would otherwise
   reconstruct a second instance. ``NO_VALUE``, ``NO_DEFAULT`` and ``ABSENT`` have none.
   Measured, since the consequence differs: ``NO_DEFAULT`` survives a copy identically
   anyway, because its ``__new__`` hands back the cached instance, while
   ``copy.copy(NO_VALUE)`` and ``copy.copy(ABSENT)`` each build a distinct object that
   fails both ``is`` and ``==``. Neither is reached by a copy that would notice:
   ``ABSENT`` never leaves the
   module that reads it, and ``NO_VALUE``, though it rides
   :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>` through a
   field copy once per field per packet, keeps its identity there because
   :meth:`FieldBase.__copy__ <pcapkit.corekit.fields.field.FieldBase.__copy__>` is
   shallow and shares the reference. Add all three when, and only when, the sentinel
   becomes reachable from a copy that is not.

