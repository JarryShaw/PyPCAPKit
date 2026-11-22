.. _public-signatures:

Public Signatures
-----------------

How a public callable takes its arguments: the functions of :mod:`pcapkit.interface`,
the public classes of :mod:`pcapkit.foundation`, and
:class:`~pcapkit.protocols.protocol.Protocol` and its subclasses. Ruled by the owner on
:issue:`2834`, over one configuration object held in a context variable, which would
move each call's contract out of its signature. A public signature that breaks a rule
here is brought into line by a change of its own.

The Rules
~~~~~~~~~

#. **The primary input stays positional, and everything after it is keyword-only**, so
   adding a parameter moves no other.
#. **One name per concept.** ``layer``, ``protocol``, ``context``, ``strict`` and
   ``store`` mean the same wherever they appear. A format is ``format``, never
   ``fmt``; ``timeout`` is a number of seconds, never a flag; a callback is added by
   ``register_callback(callback, *, index=None)``, under no second name; and
   ``analyze`` is the one spelling, for a keyword as for a method.
#. **A wrapper mirrors the signature of what it wraps** -- a :mod:`pcapkit.interface`
   function that of the class it builds -- and a test pins the two equal.
#. **A real default is written in the signature.** :obj:`None` means off, never a
   default chosen out of sight.
#. **A keyword set is closed.** An unknown keyword is refused, never accepted and
   ignored.

Feature Options
~~~~~~~~~~~~~~~

**A feature's options are grouped in a** ``*Options`` **class**, whose fields take the
keyword names of the class the feature configures. The feature's own keyword takes:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Value
     - Means
   * - :obj:`None` or ``[]``
     - the feature is off
   * - a list of registered names
     - shorthand for the options object naming them, its other fields at their
       defaults
   * - the options object
     - the feature is on, as the object configures it

So an option for a feature that is off cannot be passed at all, rather than being
silently ignored. ``[]`` meaning off was ruled in review of :pr:`2868`
(:issue:`2836`), and so were these:

*  The ``*Options`` classes are exported from :mod:`pcapkit.interface`, and so from
   :mod:`pcapkit`, beside the functions that take them.
*  A field with no real default, such as the output file or the protocol names, stays
   required rather than gaining a guessed one.
*  An unknown name, for ``layer`` as for a format or a protocol, raises
   :exc:`~pcapkit.utilities.exceptions.FormatError`, and a feature keyword of the
   wrong type raises :exc:`~pcapkit.utilities.exceptions.RegistryError`, a
   :exc:`TypeError`.

**A** ``PCAPKIT_*`` **tunable is a process-wide limit or policy; an option is per
call.** A setting a caller varies from one call to the next is a keyword, and one that
bounds the whole process, as :data:`~pcapkit.utilities.config.TCP_GAP_LIMIT` does, is
a :mod:`pcapkit.utilities.config` tunable. The ``Options`` suffix keeps the classes
from reading as those tunables.

Incompatible Changes
~~~~~~~~~~~~~~~~~~~~

**An incompatible signature change is made outright, with no shim.** A shim taking the
old keywords hides what the call accepts from its signature, which these rules exist to
show. :issue:`2594` set the precedent, for the keyword groups of ``make()``.
