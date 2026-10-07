House Conventions
=================

.. important::

   The pages below record **design rulings** for :mod:`pcapkit` -- decisions
   that are not derivable from the code, and that a future maintainer or an
   automated contributor would otherwise have to rediscover by reading a closed
   issue thread. Each ruling names where it was settled.

   :ref:`mint-criterion` and :ref:`registry-protocol` govern
   :mod:`pcapkit.const`, which is where the settled questions have mostly
   arisen. :ref:`sentinel-convention` governs :mod:`pcapkit.corekit`,
   :ref:`extension-header-subclassing` a protocol class hierarchy,
   :ref:`protocol-layer-placement` which subpackage a dissector belongs in,
   :ref:`process` the repository rather than any of its code,
   :ref:`documentation` the prose itself -- on these pages and in the API
   reference -- rather than any code at all, and :ref:`test-coverage` what the
   test suite has to prove.

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
   protocol-layer-placement
   process
   documentation
   test-coverage
