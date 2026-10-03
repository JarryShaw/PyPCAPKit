.. _mint-criterion:

Minting an Unrecognised Value
-----------------------------

121 of the 127 registries under :mod:`pcapkit.const` define ``_missing_``, which decides
what happens when a value has no member. The six without one --
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader`,
:class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` and
:class:`~pcapkit.const.reg.apptype.apptype.AppType`'s four transport subclasses -- carry
no declared-but-unassigned range for one to resolve. There are two possible behaviours,
and which one a given range gets is a **design decision, not a style preference**:

``extend_enum(cls, name, value)`` -- *mint*
   Creates a real, permanent member on the class. It is installed in
   ``_member_map_`` and ``_value2member_map_``, so it is visible to iteration,
   lookup and ``__members__`` from then on, for the life of the process.

:meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` -- *unmint*
   Returns a member-like object for the value **without** installing it. The registry
   does not grow, and a second lookup of the same value builds an equal but distinct
   object rather than handing back the first.

**Exactly one** ``_missing_`` in the tree mints:
:class:`~pcapkit.const.mh.cga_type.CGAType`'s, whose values are 128-bit CGA extension
tags rather than an IANA-style range of codes. 114 unmint, and the remaining six -- the
five flag registries and :class:`~pcapkit.const.hip.transport.Transport` -- only
range-check and hand back to ``super()._missing_``, declaring no unassigned range at
all. So outside ``CGAType`` the criterion below decides the *name* an unregistered member
carries rather than whether it registers: the registrar's own label suffixed with the
individual code, or the bare block label on its own. The two crawlers that generate the
ranges record that narrowing in their own comments:
:file:`pcapkit/vendor/reg/ethertype.py`'s ``UNASSIGNED_ROW_NAMES`` and
:file:`pcapkit/vendor/ipx/socket.py`'s ``UNASSIGNED_RANGE_NAMES``.

.. mermaid::

   flowchart TD
       LOOKUP["cls(value) finds no member"] --> MISSING["_missing_"]
       MISSING -->|"out of range, or no block covers it"| RAISE["ValueError"]
       MISSING -->|"CGAType only"| MINT["extend_enum<br/>permanent member, registry grows"]
       MISSING -->|"block label names a party"| SUFFIXED["_unregistered_member<br/>label + _0x&lt;code&gt;"]
       MISSING -->|"block label names a procedure"| BARE["_unregistered_member<br/>bare block label"]

The Criterion
~~~~~~~~~~~~~

The test, paraphrased from the maintainer's ruling: does the upstream registry treat
the label as the final, concrete assigned name, or only as a notation for a human
reading the table?

Settled in review of the ``Socket._missing_`` branch-order fix
(:issue:`841`) and reaffirmed
on :issue:`775` as a core concept of
the ruling.

So the question to ask of a range is **what the upstream registry actually did**, not
what the generated code happens to look like:

*  The source assigns a **real, specific name** to those codes. The name records
   something the registry genuinely says, so it is carried across and suffixed with the
   code it belongs to.
*  The source says only that the codes are spoken for, without naming them --
   ``Unassigned``, ``Reserved``, ``Reserved for Private Use``,
   ``Reserved for Experimental Use``, ``Deprecated``, ``Dynamically Assigned``
   and ``Statically Assigned``. These are written for a human reading the table, so the
   bare label stands: suffixing one with a code would **manufacture a name nobody
   assigned**, and the value will get its real name if and when something assigns it.

Worked Examples
~~~~~~~~~~~~~~~

*Bare label.* :mod:`pcapkit.const.ipx.socket`'s ``Dynamically Assigned``,
``Dynamically Assigned Socket Numbers``, ``Statically Assigned Socket Numbers`` and
``Experimental`` ranges. Each names **how the socket will be allocated**, not what
occupies it; the real name arrives with the allocation.

*Suffixed.* :mod:`pcapkit.const.reg.ethertype`'s company names -- ``Xyplex``,
``Datability``, ``Qualcomm``, ``Motorola`` and forty-two others, 46 names across 50
range blocks, since four of them hold two blocks each -- and
:mod:`pcapkit.const.ipx.socket`'s ``Registered by Xerox``. A company name is the
assignment, for the reason in the next section.

Two further ranges in that file carry a suffixed name without being company names at
all: ``IEEE802.3 Length Field``, which names a field in a standard, and
``Berkeley Trailer encap/IP``, which names an encapsulation. Both are outside the 46,
and neither is suffixed for the reason the next section gives.

.. note::

   Those two groups look alike and the line between them is **not** range-versus-single
   code. ``Registered by Xerox`` covers a range and is still suffixed per socket,
   because it names *who registered the socket*. ``Dynamically Assigned`` also covers a
   range and is not, because it names only the *mechanism* by which some future party
   will take it. Ask what the label tells you: a party, or a procedure.

Suffixed Company Names
~~~~~~~~~~~~~~~~~~~~~~

The ethertype case looks like an exception to the rule and is not. The maintainer's
reasoning, settled on :issue:`775` after
being raised in review of the same ``Socket._missing_`` fix
(:issue:`841`): a proprietary protocol
will never have a public name, so the company name is what serves that purpose in its
place.

So the company name is not a note *about* the code -- it is the best name that will ever
exist *for* it, which makes it the final concrete assigned name under the test above.
That is also why ``DEC Unassigned`` goes the other way despite carrying the same
attribution: there the company holds the block and assigned nothing, so the notation is
"Unassigned" and the attribution is incidental.

Checking the Current State
~~~~~~~~~~~~~~~~~~~~~~~~~~

The split is measurable rather than a matter of memory. Slice each ``_missing_`` body
and see which call it makes -- an :mod:`ast` walk is reliable where a text search is
not, because ``extend_enum`` also appears in imports and in prose. Match on the
attribute name as well as on the bare name: ``extend_enum`` is called as a plain
function, but ``_unregistered_member`` is called on ``cls``, so a walk that inspects
only ``ast.Name`` nodes finds every mint and no unmint at all:

.. code-block:: python

   import ast, pathlib

   for path in sorted(pathlib.Path('pcapkit/const').rglob('*.py')):
       if path.name == '__init__.py':
           continue
       tree = ast.parse(path.read_text())
       for node in ast.walk(tree):
           if isinstance(node, ast.FunctionDef) and node.name == '_missing_':
               calls = {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
                        for n in ast.walk(node) if isinstance(n, ast.Call)
                        and isinstance(n.func, (ast.Name, ast.Attribute))}
               if 'extend_enum' in calls:
                   print('MINT  ', path)
               elif '_unregistered_member' in calls:
                   print('UNMINT', path)

.. warning::

   Calling ``Cls(value)`` on a registry whose ``_missing_`` mints **mutates the
   class**. A probe is not a read: it installs a member that every later lookup then
   finds. :class:`~pcapkit.const.mh.cga_type.CGAType` is the one registry this applies
   to today, but snapshot ``{member.value for member in Cls}`` before any lookup
   regardless, and use a throwaway process per registry when comparing behaviour across
   revisions.
