Glossary
========

Some words in these docs carry more than one meaning. Each entry says which
sense applies where, and links to the page that explains it.

.. glossary::

   data model
       A :class:`~pcapkit.protocols.data.data.Data` subclass, or an instance of
       one: a protocol's fields as parsed values, which :attr:`Protocol.info
       <pcapkit.protocols.protocol.Protocol.info>` returns, as against the raw
       octets of :attr:`Protocol.data <pcapkit.protocols.protocol.Protocol.data>`.
       Its base, :class:`~pcapkit.corekit.infoclass.Info`, models the library's
       other records too, such as the reassembly ones; :ref:`ext-new-protocol`
       explains it.

   default engine
       The engine that ``engine='default'`` (also spelled ``'pcapkit'``) selects,
       and the one an unknown or unavailable engine falls back to: the built-in
       :class:`~pcapkit.foundation.engines.pcap.PCAP` and
       :class:`~pcapkit.foundation.engines.pcapng.PCAPNG` readers, picked by the
       input's magic number (:doc:`pcapkit/foundation/engines/builtin`).

   info
       On a protocol, :attr:`Protocol.info
       <pcapkit.protocols.protocol.Protocol.info>`: its :term:`data model`, which
       the enclosing layer's holds under :attr:`Protocol.info_name
       <pcapkit.protocols.protocol.Protocol.info_name>`
       (:doc:`pcapkit/protocols/protocol`). Elsewhere, an
       :class:`~pcapkit.corekit.infoclass.Info` instance, such as the
       :term:`reasm.tcp.packet` record that reassembly takes as ``info``
       (:doc:`pcapkit/corekit/infoclass`).

   registry
       One of these, told apart by context:

       * an upstream registry, such as an IANA protocol number registry, that
         the crawlers fetch (:doc:`pcapkit/vendor/index`);
       * the :mod:`pcapkit.const` enumeration generated from one, such as
         :class:`~pcapkit.const.reg.ethertype.EtherType`
         (:doc:`pcapkit/const/index`);
       * a dispatch table from a code or name to the class that handles it,
         such as :attr:`Protocol.__proto__
         <pcapkit.protocols.protocol.Protocol.__proto__>` or
         :attr:`Extractor.__engine__
         <pcapkit.foundation.extraction.Extractor.__engine__>`, and the
         registration functions that write to one
         (:doc:`pcapkit/foundation/registry`);
       * :attr:`EnumMeta.registry
         <pcapkit.protocols.schema.schema.EnumMeta.registry>`, the mapping from
         an enumeration member to the :term:`schema` that parses it.

   schema
       A :class:`~pcapkit.protocols.schema.schema.Schema` subclass, which lays
       out a protocol header's fields as they sit on the wire, or an instance of
       one: the header as read or built, which :attr:`Protocol.schema
       <pcapkit.protocols.protocol.Protocol.schema>` returns. It is not the
       :term:`data model`; :ref:`ext-new-protocol` explains the pair.
