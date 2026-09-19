.. This page is a thin wrapper around the repository-root ``CHANGELOG.rst``,
   which is the single source of truth. It lives at the root rather than here
   because ``MANIFEST.in`` carries both ``global-include *.rst`` and
   ``prune docs``: a changelog kept only under ``docs/`` would be absent from
   every source distribution, which is where packagers read it. A copy in both
   places would drift, so this file duplicates no content.

   Deliberately no title of its own. The included file opens with its own
   ``Changelog`` document title, which becomes this page's title and its
   toctree label; adding a second one here renders two ``<h1>`` elements on the
   same page. Measured, not assumed -- a stub carrying its own title produced
   ``h1 Release Notes`` followed by ``h1 Changelog``.

.. include:: ../../CHANGELOG.rst
