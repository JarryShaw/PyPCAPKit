==============
Dump Utilities
==============

.. module:: pcapkit.dumpkit

:mod:`pcapkit.dumpkit` is the collection of :mod:`pcapkit`'s own dumpers,
like those in :mod:`dictdumper`.

.. toctree::
   :maxdepth: 2

   common
   pcap
   null

Every dumper class is a :class:`dictdumper.dumper.Dumper` subclass, responsible
for writing parsed packet data into a formatted output file. The class
hierarchy:

.. mermaid::

   flowchart LR
       A{{Dumper}} --> D([other customisation ...])

       subgraph builtins [Built-in Dumpers]
           Tree & XML & JSON
           XML --> PLIST
           JSON -- deprecated --x VueJS
       end
       A --> Tree & XML & JSON

       subgraph pcapkit [PyPCAPKit Dumpers]
           DumperBase --> PCAPIO & NotImplementedIO
           DumperBase --> Dumper --> E([user customisation ...])
       end
       A --> DumperBase

       click A "https://dictdumper.jarryshaw.me/en/latest/dictdumper.dumper.html#dictdumper.dumper.Dumper"

       click Tree "https://dictdumper.jarryshaw.me/en/latest/dictdumper.tree.html#dictdumper.tree.Tree"
       click XML "https://dictdumper.jarryshaw.me/en/latest/dictdumper.xml.html#dictdumper.xml.XML"
       click JSON "https://dictdumper.jarryshaw.me/en/latest/dictdumper.json.html#dictdumper.json.JSON"
       click PLIST "https://dictdumper.jarryshaw.me/en/latest/dictdumper.plist.html#dictdumper.plist.PLIST"
       click VueJS "https://dictdumper.jarryshaw.me/en/latest/dictdumper.vuejs.html#dictdumper.vuejs.VueJS"

       click DumperBase "common.html#pcapkit.dumpkit.common.DumperBase"
       click Dumper "common.html#pcapkit.dumpkit.common.Dumper"
       click PCAPIO "pcap.html#pcapkit.dumpkit.pcap.PCAPIO"
       click NotImplementedIO "null.html#pcapkit.dumpkit.null.NotImplementedIO"

.. note::

   The ``tree`` output (also selected as ``text`` and ``txt``) is a lossy,
   human-readable view, and nothing reads it back. It renders ``''``, ``b''``,
   :data:`None` and ``{}`` all as ``NIL``, writes a newline inside a short
   string as is, breaking the layout, and rewraps a longer one, turning its
   newlines into spaces. Use ``json`` or ``plist`` (also selected as
   ``xml``) where the report has to round-trip.
