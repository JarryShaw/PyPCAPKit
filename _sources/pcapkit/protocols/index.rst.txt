Protocol Family
===============

.. module:: pcapkit.protocols

:mod:`pcapkit.protocols` is collection of all protocol families,
with detailed implementation and methods.

.. toctree::
   :maxdepth: 2

   protocol
   misc/index
   link/index
   internet/index
   transport/index
   application/index

Protocol Registry
-----------------

.. data:: pcapkit.protocols.__proto__
   :type: dict[str, Type[Protocol]]

   Protocol registry.

   .. seealso::

      Please refer to :func:`pcapkit.foundation.registry.register_protocol`
      for more information.
