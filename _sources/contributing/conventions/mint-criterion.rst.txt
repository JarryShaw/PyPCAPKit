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

The test, paraphrased from the maintainer's ruling: does the upstream registry treat
the label as the final, concrete assigned name (**mint**), or only as a notation for a
human reading the table (**unmint**)?

Settled on `#847 <https://github.com/JarryShaw/PyPCAPKit/issues/847>`__ and reaffirmed
on `#775 <https://github.com/JarryShaw/PyPCAPKit/issues/775>`__ as a core concept of
the ruling.

So the question to ask of a range is **what the upstream registry actually did**, not
what the generated code happens to look like:

*  The source assigns a **real, specific name** to those codes -- minting records
   something the registry genuinely says. **Mint.**
*  The source says only that the codes are spoken for, without naming them --
   ``Unassigned``, ``Reserved``, ``Reserved for Private Use``,
   ``Reserved for Experimental Use``, ``Deprecated``, ``Dynamically Assigned``
   and ``Statically Assigned``. These are written for a human reading the
   table. Minting them **manufactures a name nobody
   assigned**, and the value will get its real name if and when something assigns
   it. **Unmint.**

Worked examples
~~~~~~~~~~~~~~~

*Unmint.* :mod:`pcapkit.const.ipx.socket`'s ``Dynamically Assigned``,
``Dynamically Assigned Socket Numbers``, ``Statically Assigned Socket Numbers`` and
``Experimental`` ranges. Each names **how the socket will be allocated**, not what
occupies it; the real name arrives with the allocation.

*Mint.* :mod:`pcapkit.const.reg.ethertype`'s company names -- ``Xyplex``,
``Datability``, ``Qualcomm``, ``Motorola`` and forty-two others, 46 names across 50
range blocks, since four of them hold two blocks each -- and, in the same file's
neighbour, :mod:`pcapkit.const.ipx.socket`'s ``Registered by Xerox``. A company name
is the assignment, for the reason in the next section.

Two further ranges in that file mint without being company names at all:
``IEEE802.3 Length Field``, which names a field in a standard, and
``Berkeley Trailer encap/IP``, which names an encapsulation. Both are outside the 46,
and neither mints for the reason the next section gives.

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
being raised on `#847 <https://github.com/JarryShaw/PyPCAPKit/issues/847>`__: a
proprietary protocol will never have a public name, so the company name is what serves
that purpose in its place.

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

