House Conventions
=================

.. important::

   The pages below record **design rulings** for :mod:`pcapkit` -- decisions
   that are not derivable from the code, and that a future maintainer or an
   automated contributor would otherwise have to rediscover by reading a closed
   issue thread. Each ruling names where it was settled.

   What each page governs:

   * :ref:`mint-criterion` -- :mod:`pcapkit.const`, which is where the settled
     questions have mostly arisen;
   * :ref:`sentinel-convention` -- :mod:`pcapkit.corekit`;
   * :ref:`registry-protocol` -- :mod:`pcapkit.const` again, and the registration
     wrappers of :mod:`pcapkit.foundation.registry`;
   * :ref:`extension-header-subclassing` -- a protocol class hierarchy;
   * :ref:`protocol-family-grouping` -- how a protocol family's base and members
     spell :meth:`~pcapkit.protocols.protocol.Protocol.id`, how a protocol class
     is named after its module, and how quietly a next-layer fallback keeps a
     refused layer as :class:`~pcapkit.protocols.misc.raw.Raw`;
   * :ref:`protocol-member-order` -- the order of members in a protocol class body;
   * :ref:`protocol-layer-placement` -- which subpackage a dissector belongs in;
   * :ref:`process` -- the repository rather than any of its code;
   * :ref:`documentation` -- the prose itself, on these pages and in the API
     reference, rather than any code at all;
   * :ref:`test-coverage` -- what the test suite has to prove;
   * :ref:`utilities-or-corekit` -- which of :mod:`pcapkit.utilities` and
     :mod:`pcapkit.corekit` a support module belongs in;
   * :ref:`reassembly-integration` -- :mod:`pcapkit.foundation.reassembly` and what a
     new engine there needs from :mod:`pcapkit.toolkit` and
     :mod:`pcapkit.foundation.analysis`;
   * :ref:`const-vendor-pairing` -- :mod:`pcapkit.const` and the
     :mod:`pcapkit.vendor` crawler each module needs.

   **A ruling that stays in its thread is a ruling that gets rediscovered.** So
   when a question is answered in a way the code cannot express on its own -- a
   classification, a naming rule, a deliberate asymmetry -- it is written onto
   the page that covers it in the same change that implements it, rather than
   left in the issue for the next contributor to find. That is the owner's
   standing ask on
   :issue:`918`.

.. toctree::
   :maxdepth: 1

   mint-criterion
   sentinel-convention
   registry-protocol
   extension-header-subclassing
   protocol-family-grouping
   protocol-member-order
   protocol-layer-placement
   process
   documentation
   test-coverage
   utilities-or-corekit
   reassembly-integration
   const-vendor-pairing
