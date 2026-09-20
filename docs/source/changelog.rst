.. The changelog's index. Every entry is its own document under
   ``changelog/``, one per released version, and this page is the title, the
   preamble and the table of contents over them -- there is exactly one copy of
   each entry and nothing to keep in step by hand.

   The repository root carries ``CHANGELOG.md`` rather than a second copy of
   this history. It holds only the version being released, in Markdown, because
   its consumers are the ``Create Release`` workflow's release body and the
   source distribution, and both of those read Markdown. It is generated from
   ``changelog/<version>.rst``, so this tree stays the single source.

   The preamble below is verbatim from the single-file changelog it replaces.

=========
Changelog
=========

All notable changes to PyPCAPKit are recorded here.

   **Note** -- Versions before 1.5.0 are reconstructed from the git history, so
   they summarise each release rather than enumerate every change. The record
   starts at 0.13.0 (2018-12-08); the earlier 0.x releases are not covered.

   **Note** -- Post-releases (``X.Y.Z.postN``) are, from 1.0.1 onwards, automated
   publications of the weekly registry refresh: a bot regenerates the vendor
   constant enumerations under ``pcapkit.const`` from the upstream IANA
   registries and bumps the version. They carry no library changes, and are
   collapsed into a single line per release below. Where a post-release did
   carry something real, it is called out.

Each release has its own page below, newest first. The repository root's
:file:`CHANGELOG.md` carries only the version currently being released; this is
the whole history.

.. toctree::
   :maxdepth: 1

   changelog/1.5.0
   changelog/1.4.1
   changelog/1.4.0
   changelog/1.3.5
   changelog/1.3.4
   changelog/1.3.3
   changelog/1.3.1
   changelog/1.3.0
   changelog/1.2.2
   changelog/1.2.1
   changelog/1.2.0
   changelog/1.1.1
   changelog/1.1.0
   changelog/1.0.3
   changelog/1.0.2
   changelog/1.0.1
   changelog/1.0.0
   changelog/0.16.3
   changelog/0.16.2
   changelog/0.16.1
   changelog/0.16.0
   changelog/0.15.5
   changelog/0.15.4
   changelog/0.15.3
   changelog/0.15.2
   changelog/0.15.1
   changelog/0.15.0
   changelog/0.14.5
   changelog/0.14.4
   changelog/0.14.3
   changelog/0.14.2
   changelog/0.14.1
   changelog/0.14.0
   changelog/0.13.3
   changelog/0.13.2
   changelog/0.13.1
   changelog/0.13.0
