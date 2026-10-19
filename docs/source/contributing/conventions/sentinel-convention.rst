.. _sentinel-convention:

Naming a Sentinel
-----------------

A *sentinel* here is a module-level singleton whose only job is to be recognised by
identity -- ``value is SENTINEL`` -- so that it can never be confused with a value a
caller might legitimately pass. The house rule, from the maintainer, covers the type:
the sentinel object's type class is named ``<SENTINEL>Type``.

That is, the class takes the instance's name in CamelCase with ``Type`` appended. It
says nothing about the **object**'s own name, which is what let the casings diverge
with no rule naming any of them wrong. GitHub issue :issue:`937` closed that gap: the
owner ruled for SCREAMING_SNAKE and accepted the resulting breaking change outright, with
no backport. So the object is named in SCREAMING_SNAKE and the type-naming rule above
derives from it mechanically -- title-case each underscore-separated word and append
``Type``, no per-sentinel exception needed. The sentinels in the tree follow it:

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

GitHub issue :issue:`911`'s housing ruling -- one module for all of them -- is why the table
names a single defining module, and it is the only import path. The modules that *use* a
sentinel import it from there but do not re-export it: :issue:`1744` dropped the
per-module re-exports, under the ruling on :issue:`1715` that a moved name keeps no
re-export at its old path. Import the object, and the type for an annotation, from
:mod:`pcapkit.corekit.sentinels`.

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
that the objects alone -- ``NULL`` and its siblings -- are exported to users, so a
public sentinel names its instance in :mod:`pcapkit.corekit.sentinels`'s ``__all__`` and
leaves the type out of it. The type stays importable by its dotted path there, for an
annotation or an ``is`` guard; it is only ``import *`` that does not offer it. The
``__all__`` there does name :class:`~pcapkit.corekit.sentinels.Sentinel`, the abstract
base every sentinel type shares, since that is no sentinel's own type. A private
sentinel such as ``ABSENT`` is in neither, which is what private means here -- dropping
its leading underscore did not add it to either list, and
:class:`~pcapkit.corekit.sentinels.AbsentType` and
:data:`~pcapkit.corekit.sentinels.ABSENT` are documented on
:doc:`the sentinels API page </pcapkit/corekit/sentinels>` as private and not for
public use rather than left off it, since the name alone no longer says so.

.. note::

   Every sentinel type subclasses :class:`~pcapkit.corekit.sentinels.Sentinel`, the public
   abstract base that carries the singleton protocol, the repr and the immutability, and
   whose metaclass is :class:`~pcapkit.corekit.sentinels.SentinelMeta`. So a new sentinel
   is short: subclass it, set ``__slots__ = ()`` and ``_name`` to the object's name, and
   add ``__bool__`` if the sentinel stands for an absent value.
   :class:`~pcapkit.corekit.sentinels.NoValueType` is the smallest example. Everything
   goes in the ``class`` body, since the type refuses any attribute set on it afterwards.

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
   default: 'Any' = NO_DEFAULT

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

Most of the protocol is shared and lives on ``Sentinel``. Where the sentinels differ,
the differences are **needs, not inconsistencies**:

``__new__`` returning a cached instance
   Every sentinel has it, from the base, and returns the instance the metaclass made as
   the ``class`` statement ran. It guards against a caller constructing a second,
   non-identical sentinel that then fails every ``is`` check, and it hands back the
   cached instance rather than raising, as ``type(None)()`` does, so that mistake
   corrects itself.
   :class:`~pcapkit.corekit.sentinels.NullType` documents the limit honestly: a module
   **reload** re-executes the class statement, so the guard does not survive one, and
   code holding the pre-reload instance will fail ``is``. The module that matters there
   is :mod:`pcapkit.corekit.sentinels`, where the class statement lives; reloading one
   of the modules that imports a sentinel from there has no effect on it.

``__bool__`` returning :obj:`False`
   ``NULL``, ``NO_VALUE`` and ``ABSENT`` have it, because each stands for an *absent
   value* and reads naturally in a boolean test. ``NO_DEFAULT`` deliberately does
   **not**: it is a marker meaning *no default was supplied*, it is only ever tested
   with ``is``, and making it falsy would invite ``if not default:`` -- which would
   then treat a caller's genuine falsy default (``0``, ``''``, :obj:`None`,
   :obj:`False`) the same as the sentinel, the very confusion the sentinel exists to
   prevent.

``__copy__`` / ``__deepcopy__`` / ``__reduce__``
   Every sentinel has them, from the base. The owner ruled on :issue:`1842` that every
   sentinel is a true singleton, rather than gaining these only once a deep copy is
   found to reach it -- as one had by then, through a parsed schema and a field that
   hold ``NO_VALUE``. ``__copy__`` and ``__deepcopy__`` return the object itself, and
   ``__reduce__`` returns its module-level name, so :mod:`pickle` stores a reference to
   that name and every protocol loads the same object back. A guarded ``__new__``
   alone would not do, since pickle protocols 0 and 1 rebuild through
   ``copyreg._reconstructor``, which calls :meth:`object.__new__` directly. That
   path also limits pickles written before :issue:`1842`: one of ``NO_VALUE``,
   ``NO_DEFAULT`` or ``ABSENT`` at protocol 0 or 1 still loads, but as a second
   instance, because nothing on the class can intercept it.

``__repr__``
   Every sentinel has it, from the base. It is the object's own name -- ``NULL``,
   ``NO_VALUE``, ``NO_DEFAULT``, ``ABSENT`` -- as ``repr(None)`` is ``'None'``, and
   :class:`str` gives the same. That is what a signature, :func:`help` and a traceback
   show.

``__setattr__`` / ``__delattr__``
   Every sentinel has them, from the base, and they raise :exc:`AttributeError` for any
   name, as ``None.x = 1`` does. ``__slots__`` is empty, so there is no ``__dict__`` to
   reach round them either. The metaclass does the same for the type, raising
   :exc:`TypeError` as ``type(None).x = 1`` does, so neither ``_name`` nor the cached
   instance can be swapped out. It also refuses to let a concrete sentinel type be
   subclassed, by a ``class`` statement or by ``register``, as ``type(None)`` cannot be;
   ``Sentinel`` itself stays subclassable, being abstract. The owner asked for this in
   review of the change for :issue:`1842`: a sentinel's repr and its other behaviour
   follow Python's own singletons, :obj:`None`, :obj:`Ellipsis` and
   :obj:`NotImplemented`.

