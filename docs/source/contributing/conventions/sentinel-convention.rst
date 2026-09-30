.. _sentinel-convention:

Naming a sentinel
-----------------

A *sentinel* here is a module-level singleton whose only job is to be recognised by
identity -- ``value is SENTINEL`` -- so that it can never be confused with a value a
caller might legitimately pass. The house rule, from the maintainer, covers the type:
the sentinel object's type class is named ``<SENTINEL>Type``.

That is, the class takes the instance's name in CamelCase with ``Type`` appended. It
says nothing about the **object**'s own name, which is what let three casings diverge
with no rule naming any of them wrong. GitHub issue #937 closed that gap: the owner
ruled for SCREAMING_SNAKE and accepted the resulting breaking change outright, with no
backport. So the object is named in SCREAMING_SNAKE, and the type-naming rule above
derives from it
mechanically -- title-case each underscore-separated word and append ``Type``, no
per-sentinel exception needed. The four in the tree follow it:

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

All four used to live beside the one class that used them --
:mod:`pcapkit.corekit.module`, :mod:`pcapkit.corekit.fields.field`,
:mod:`pcapkit.corekit.enum` and :mod:`pcapkit.protocols.protocol` respectively.
GitHub issue #911's housing ruling -- one module for all four -- moved the four
definitions into the single shared module the table now names; each original module
keeps a re-export so every existing
``from <module> import <name>`` keeps working, including the
``if TYPE_CHECKING:``-only imports of the types.

Before GitHub issue #937, the **instance** name's casing was deliberately free, which is
why ``NULL`` and ``NoValue`` disagreed and both were called correct -- three sentinels
had already picked three different casings (``NULL`` SCREAMING_SNAKE, ``NoValue``
CamelCase, ``_Absent`` CamelCase with a leading underscore) before anyone ruled on it.
#937's ruling closes that: SCREAMING_SNAKE is now the one answer, and the two renames
it made -- ``NoValue`` to ``NO_VALUE``, ``_Absent`` to ``ABSENT`` -- are the breaking
change it accepted rather than deprecating. Where a sentinel name already exists and
already follows SCREAMING_SNAKE, keep it; renaming a published sentinel again costs
every caller for no further gain.

The rename also dropped the **leading underscore** ``_Absent``/``_AbsentType`` used to
carry. ``ABSENT`` is private -- it is read in ``_declared_keywords`` and discarded
there, never leaving :mod:`pcapkit.protocols.protocol` -- and the underscore used to be
the mechanical signal of that. The owner ruled on #937 that dropping it is fine, so
long as the documentation states that the type and class are private and not for public
use -- that alone is enough. So privacy is documentation-only from
here on, carried by this paragraph and by
:class:`~pcapkit.corekit.sentinels.AbsentType`'s own docstring
(:file:`pcapkit/corekit/sentinels.py`, line 439), which still says so:

   A distinct class rather than a bare :obj:`object` so that the sentinel has a name
   of its own in a traceback or a debugger, and so that a type checker has something
   to name where ``object()`` would give it nothing. It follows
   :class:`~pcapkit.corekit.sentinels.NoValueType`, which does the same job for an unset
   field default; this is a sibling of it rather than a reuse [...]

It remains a deliberate fourth rather than an accident: the leading underscore's
absence is also why this table once listed three for as long as it did -- a sweep
filtered on capitalised names did not see ``_Absent`` -- and that history does not
change now that nothing in the name itself marks it out. When adding a sentinel, add
it here whether or not it is public.

What reaches users is the **object only**. The owner ruled on GitHub issue #911 that
the objects alone -- ``NULL`` and its siblings -- are exported to users, so a public
sentinel names its instance in its module's ``__all__`` and leaves the type out of it.
The type stays importable by its dotted path, for an annotation or an ``is`` guard; it
is ``import *`` that no longer offers it. A private sentinel such as ``ABSENT`` is in
neither, which is what private means here -- dropping its leading underscore did not
add it to either list, and :class:`~pcapkit.corekit.sentinels.AbsentType` and
:data:`~pcapkit.corekit.sentinels.ABSENT` are documented on
:doc:`the sentinels API page </pcapkit/corekit/sentinels>` as private and not for
public use rather than left off it, since the name alone no longer says so.

.. note::

   Of the four, only :class:`~pcapkit.corekit.sentinels.NullType` is a full worked
   example. ``NoValueType`` follows the naming rule but is **not** a singleton
   (``NoValueType() is NO_VALUE`` is :obj:`False`) and has no ``__repr__`` of its own,
   so it demonstrates the name and nothing else; ``AbsentType`` has a ``__repr__``
   (``<absent>``) but no singleton guard either. Copy ``NullType`` when you need a
   pattern to follow.

Why a class and not ``object()``
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
house-style rewrite destroys that in exchange for a sentinel nobody outside those forty
lines ever sees. The rule above is for sentinels this package writes itself.

What to implement, and what not to
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The four sentinels deliberately differ, and the differences are **needs, not
inconsistencies**:

``__new__`` returning a cached instance
   Guards against a caller constructing a second, non-identical sentinel that then
   fails every ``is`` check. Worth having wherever the type is reachable by a caller at
   all -- which, since the type is kept out of ``__all__``, means wherever it is
   importable by its dotted path rather than wherever it is star-exported.
   :class:`~pcapkit.corekit.sentinels.NullType` documents the limit honestly: a module
   **reload** re-executes the class statement, so the guard does not survive one, and
   code holding the pre-reload instance will fail ``is``. Since GitHub issue #911,
   that means reloading :mod:`pcapkit.corekit.sentinels` itself -- reloading
   :mod:`pcapkit.corekit.module`, which now only re-exports the sentinel, no longer
   has any effect on it.

``__bool__`` returning :obj:`False`
   ``NULL``, ``NO_VALUE`` and ``ABSENT`` have it, because each stands for an *absent
   value* and reads naturally in a boolean test. ``NO_DEFAULT`` deliberately does
   **not**: it is a marker meaning *no default was supplied*, it is only ever tested
   with ``is``, and making it falsy would invite ``if not default:`` -- which would
   then treat a caller's genuine falsy default (``0``, ``''``, :obj:`None`,
   :obj:`False`) the same as the sentinel, the very confusion the sentinel exists to
   prevent.

``__copy__`` / ``__deepcopy__`` / ``__reduce__``
   :class:`~pcapkit.corekit.sentinels.NullType` has them because ``NULL`` is stored in a
   :class:`~pcapkit.corekit.module.ModuleDescriptor` field, so a caller's
   :func:`copy.deepcopy` or :mod:`pickle` can walk into it and would otherwise
   reconstruct a second instance. ``NO_DEFAULT`` and ``ABSENT`` have none, because
   neither is ever stored in any structure a caller copies -- one only ever appears as
   a default argument, and the other never leaves the module that reads it.
   Add them when, and only when, the sentinel becomes reachable from something
   copyable.

