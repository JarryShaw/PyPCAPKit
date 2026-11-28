Domain Name Codec
=================

.. module:: pcapkit.corekit.schema.domain_name

:mod:`pcapkit.corekit.schema.domain_name` reads and writes the label sequence of
:rfc:`1035#section-3.1`, with the compression pointers of
:rfc:`1035#section-4.1.4`, and renders it in presentation form, for DNS and for
ICMPv6's DNS Search List option (:rfc:`8106#section-5.2`).

.. versionadded:: 1.9.0

   Moved here from ``pcapkit.protocols.application.dns.schema`` (:issue:`2934`).

.. autofunction:: pcapkit.corekit.schema.domain_name.read_name
.. autofunction:: pcapkit.corekit.schema.domain_name.make_name
.. autofunction:: pcapkit.corekit.schema.domain_name.name_to_text
.. autofunction:: pcapkit.corekit.schema.domain_name.text_to_labels
