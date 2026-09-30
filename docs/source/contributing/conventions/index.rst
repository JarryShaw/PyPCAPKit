House Conventions
=================

.. important::

   The pages below record **design rulings** for :mod:`pcapkit` -- decisions
   that are not derivable from the code, and that a future maintainer or an
   automated contributor would otherwise have to rediscover by reading a closed
   issue thread. Each ruling names where it was settled.

   Most of them govern :mod:`pcapkit.const`, which is where the settled
   questions have mostly arisen, and the page was titled *Registry Conventions*
   until `#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__ widened
   it, then split it. :ref:`extension-header-subclassing` is the first ruling
   here that governs a protocol class hierarchy rather than a registry, and
   :ref:`process` the first that governs the repository rather than any of its
   code.

   **A ruling that stays in its thread is a ruling that gets rediscovered.** So
   when a question is answered in a way the code cannot express on its own -- a
   classification, a naming rule, a deliberate asymmetry -- it is written onto
   the page that covers it in the same change that implements it, rather than
   left in the issue for the next contributor to find. That is the owner's
   standing ask on
   `#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__: every
   convention settled from here on gets documented here as well.

.. toctree::
   :maxdepth: 1

   mint-criterion
   sentinel-convention
   registry-protocol
   extension-header-subclassing
   process
