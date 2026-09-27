Registry Conventions
====================

.. important::

   This page records **design rulings** for :mod:`pcapkit.const` -- decisions that
   are not derivable from the code, and that a future maintainer or an automated
   contributor would otherwise have to rediscover by reading a closed issue
   thread. Each ruling names where it was settled.

.. _mint-criterion:

When an unrecognised value may mint a member
--------------------------------------------

Every registry under :mod:`pcapkit.const` defines ``_missing_``, which decides what
happens when a value has no member. There are two possible behaviours, and which one
a given range gets is a **design decision, not a style preference**:

``extend_enum(cls, name, value)`` -- *mint*
   Creates a real, permanent member on the class. It is installed in
   ``_member_map_`` and ``_value2member_map_``, so it is visible to iteration,
   lookup and ``__members__`` from then on, for the life of the process.

:meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` -- *unmint*
   Returns a member-like object for the value **without** installing it. The
   registry does not grow, and a second lookup of the same value is indistinguishable
   from the first.

The criterion
~~~~~~~~~~~~~

The test, in the maintainer's words:

   Is this considered as the final concrete assigned name (**mint**), or just a
   notation for the readers (**unmint**)?

Settled on `#847 <https://github.com/JarryShaw/PyPCAPKit/issues/847>`__ and confirmed
as "a core concept of the ruling" on
`#775 <https://github.com/JarryShaw/PyPCAPKit/issues/775>`__.

So the question to ask of a range is **what the upstream registry actually did**, not
what the generated code happens to look like:

*  The source assigns a **real, specific name** to those codes -- minting records
   something the registry genuinely says. **Mint.**
*  The source says only that the codes are spoken for, without naming them --
   ``Unassigned``, ``Reserved``, ``Reserved for Private Use``,
   ``Reserved for Experimental Use``, ``Deprecated``, ``Dynamically Assigned``,
   ``Statically Assigned``, ``Registered by`` some organisation. These are written
   for a human reading the table. Minting them **manufactures a name nobody
   assigned**, and the value will get its real name if and when something assigns
   it. **Unmint.**

Worked examples
~~~~~~~~~~~~~~~

*Unmint.* :mod:`pcapkit.const.ipx.socket`'s ``Dynamically Assigned``,
``Dynamically Assigned Socket Numbers``, ``Statically Assigned Socket Numbers`` and
``Experimental`` ranges. Each names **how the socket will be allocated**, not what
occupies it; the real name arrives with the allocation.

*Mint.* :mod:`pcapkit.const.reg.ethertype`'s company names -- ``Xyplex``,
``Datability``, ``Qualcomm``, ``Motorola`` and some forty-five others -- and, in the
same file's neighbour, :mod:`pcapkit.const.ipx.socket`'s ``Registered by Xerox``. A
company name is the assignment, for the reason in the next section.

.. note::

   Those two groups look alike and the line between them is **not** range-versus-single
   code. ``Registered by Xerox`` covers a range and still mints, because it names *who
   registered the socket*. ``Dynamically Assigned`` also covers a range and does not,
   because it names only the *mechanism* by which some future party will take it. Ask
   what the label tells you: a party, or a procedure.

Why the company names mint
~~~~~~~~~~~~~~~~~~~~~~~~~~

The ethertype case looks like an exception to the rule and is not. The maintainer's
reasoning, settled on `#775 <https://github.com/JarryShaw/PyPCAPKit/issues/775>`__ after
being raised on `#847 <https://github.com/JarryShaw/PyPCAPKit/issues/847>`__:

   Proprietary protocols won't have public names so company names serve this purpose.

So the company name is not a note *about* the code -- it is the best name that will ever
exist *for* it, which makes it the final concrete assigned name under the test above.
That is also why ``DEC Unassigned`` goes the other way despite carrying the same
attribution: there the company holds the block and assigned nothing, so the notation is
"Unassigned" and the attribution is incidental.

Checking the current state
~~~~~~~~~~~~~~~~~~~~~~~~~~

The split is measurable rather than a matter of memory. Slice each ``_missing_`` body
and see which call it makes -- an :mod:`ast` walk is reliable where a text search is
not, because ``extend_enum`` also appears in imports and in prose:

.. code-block:: python

   import ast, pathlib

   for path in sorted(pathlib.Path('pcapkit/const').rglob('*.py')):
       if path.name == '__init__.py':
           continue
       tree = ast.parse(path.read_text())
       for node in ast.walk(tree):
           if isinstance(node, ast.FunctionDef) and node.name == '_missing_':
               calls = {n.func.id for n in ast.walk(node)
                        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
               if 'extend_enum' in calls:
                   print('MINT  ', path)
               elif '_unregistered_member' in calls:
                   print('UNMINT', path)

.. warning::

   Calling ``Cls(value)`` on a registry whose ``_missing_`` mints **mutates the
   class**. A probe is not a read: it installs a member that every later lookup then
   finds. Snapshot ``{member.value for member in Cls}`` before any lookup, and use a
   throwaway process per registry when comparing behaviour across revisions.

.. _sentinel-convention:

Naming a sentinel
-----------------

A *sentinel* here is a module-level singleton whose only job is to be recognised by
identity -- ``value is SENTINEL`` -- so that it can never be confused with a value a
caller might legitimately pass. The house rule, from the maintainer:

   Keep the sentinel object's type class naming as ``<SENTINEL>Type``.

That is, the class takes the instance's name in CamelCase with ``Type`` appended. The
three in the tree follow it:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Instance
     - Type
     - Defined in
   * - ``NULL``
     - ``NullType``
     - :mod:`pcapkit.corekit.module`
   * - ``NoValue``
     - ``NoValueType``
     - :mod:`pcapkit.corekit.fields.field`
   * - ``NO_DEFAULT``
     - ``NoDefaultType``
     - :mod:`pcapkit.corekit.enum`

Note what the rule does **not** fix: the **instance** name's casing is deliberately
free, which is why ``NULL`` and ``NoValue`` disagree and both are correct. Pick
whichever reads better at the call site, and where a name already exists, keep it --
renaming a published sentinel costs every caller for no gain.

.. note::

   Of the three, only :class:`~pcapkit.corekit.module.NullType` is a full worked
   example. ``NoValueType`` follows the naming rule but is **not** a singleton
   (``NoValueType() is NoValue`` is :obj:`False`) and has no ``__repr__`` of its own,
   so it demonstrates the name and nothing else. Copy ``NullType`` when you need a
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

What to implement, and what not to
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The three sentinels deliberately differ, and the differences are **needs, not
inconsistencies**:

``__new__`` returning a cached instance
   Guards against a caller constructing a second, non-identical sentinel that then
   fails every ``is`` check. Worth having wherever the type is exported.
   :class:`~pcapkit.corekit.module.NullType` documents the limit honestly: a module
   **reload** re-executes the class statement, so the guard does not survive one, and
   code holding the pre-reload instance will fail ``is``.

``__bool__`` returning :obj:`False`
   ``NULL`` and ``NoValue`` have it, because each stands for an *absent value* and
   reads naturally in a boolean test. ``NO_DEFAULT`` deliberately does **not**: it is a
   marker meaning *no default was supplied*, it is only ever tested with ``is``, and
   making it falsy would invite ``if not default:`` -- which would then treat a
   caller's genuine falsy default (``0``, ``''``, :obj:`None`, :obj:`False`) the same
   as the sentinel, the very confusion the sentinel exists to prevent.

``__copy__`` / ``__deepcopy__`` / ``__reduce__``
   :class:`~pcapkit.corekit.module.NullType` has them because ``NULL`` is stored in a
   :class:`~pcapkit.corekit.module.ModuleDescriptor` field, so a caller's
   :func:`copy.deepcopy` or :mod:`pickle` can walk into it and would otherwise
   reconstruct a second instance. ``NO_DEFAULT`` has none, because it is never stored
   in any structure a caller copies -- it only ever appears as a default argument.
   Add them when, and only when, the sentinel becomes reachable from something
   copyable.

.. _registry-protocol:

Where the registry protocol lives
---------------------------------

:meth:`~pcapkit.corekit.enum.EnumRegistry.get`,
:meth:`~pcapkit.corekit.enum.EnumRegistry.get_all`,
:meth:`~pcapkit.corekit.enum.EnumRegistry.register` and
:meth:`~pcapkit.corekit.enum.EnumRegistry.register_alias` are expected to exist on
**every** registry, per the ruling on
`#842 <https://github.com/JarryShaw/PyPCAPKit/issues/842>`__. They come from
:class:`~pcapkit.corekit.enum.EnumRegistry`, mixed in ahead of the enum base so that
``_member_type_`` still resolves to :class:`int` or :class:`str`:

.. code-block:: python

   class LinkType(EnumRegistry, IntEnum):
       ...

A handful of registries define their own ``__new__`` to carry extra attributes and so
do not share the generated template; bringing them onto the base is tracked in
`#860 <https://github.com/JarryShaw/PyPCAPKit/issues/860>`__, which also records why
it cannot simply be done -- the base's string-key path does not fall through to a
value lookup, so a :class:`~aenum.StrEnum` registry would stop resolving a valid
value that is not also a name.

.. seealso::

   :mod:`pcapkit.vendor` generates these modules. A change to the shape of a
   generated registry belongs in the crawler or in
   :mod:`pcapkit.vendor.default`'s template, never in the generated file alone --
   the next regeneration would discard it.
