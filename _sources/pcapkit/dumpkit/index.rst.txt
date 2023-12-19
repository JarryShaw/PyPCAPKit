==============
Dump Utilities
==============

.. module:: pcapkit.dumpkit

:mod:`pcapkit.dumpkit` is the collection of dumpers for
:mod:`pcapkit` implementation, which is alike those described
in :mod:`dictdumper`.

.. toctree::
   :maxdepth: 2

   pcap
   null
   common

All dumper classes are implemented as :class:`dictdumper.dumper.Dumper`
subclasses, which are responsible for writing the parsed packet data into
formatted output files. Below is a brief diagram of the class hierarchy
of :mod:`pcapkit.dumpkit`:

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
           DumperBase --> Dumper --> PCAPIO & NotImplementedIO
           Dumper --> E([user customisation ...])
       end
       A --> DumperBase

       click A "https://dictdumper.jarryshaw.me/en/latest/dictdumper.dumper.html#dictdumper.dumper.Dumper"

       click Tree "https://dictdumper.jarryshaw.me/en/latest/dictdumper.tree.html#dictdumper.tree.Tree"
       click XML "https://dictdumper.jarryshaw.me/en/latest/dictdumper.xml.html#dictdumper.xml.XML"
       click JSON "https://dictdumper.jarryshaw.me/en/latest/dictdumper.json.html#dictdumper.json.JSON"
       click PLIST "https://dictdumper.jarryshaw.me/en/latest/dictdumper.plist.html#dictdumper.plist.PLIST"
       click VueJS "https://dictdumper.jarryshaw.me/en/latest/dictdumper.vuejs.html#dictdumper.vuejs.VueJS"

       click DumperBase "/pcapkit/dumpkit/common.html#pcapkit.dumpkit.common.DumperBase"
       click Dumper "/pcapkit/dumpkit/common.html#pcapkit.dumpkit.common.Dumper"
       click PCAPIO "/pcapkit/dumpkit/pcap.html#pcapkit.dumpkit.pcap.PCAPIO"
       click NotImplementedIO "/pcapkit/dumpkit/pcap.html#pcapkit.dumpkit.pcap.NotImplementedIO"
