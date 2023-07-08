Protocol Family
===============

.. module:: pcapkit.protocols
.. module:: pcapkit.protocols.data
.. module:: pcapkit.protocols.schema

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

.. autodata:: pcapkit.protocols.__proto__
   :no-value:

   .. seealso::

      Please refer to :func:`pcapkit.foundation.registry.register_protocol`
      for more information.

Header Schema
-------------

.. module:: pcapkit.protocols.schema.schema

.. autoclass:: pcapkit.protocols.schema.schema.Schema
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: __payload__
   .. autoattribute:: __additional__
      :no-value:
   .. autoattribute:: __excluded__
      :no-value:

.. autoclass:: pcapkit.protocols.schema.schema.EnumSchema
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: __default__
      :no-value:
   .. autoattribute:: __enum__
      :no-value:

.. autodecorator:: pcapkit.protocols.schema.schema.schema_final

Meta Classes
~~~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.schema.SchemaMeta
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.schema.EnumMeta
   :members:
   :show-inheritance:

Data Model
----------

.. module:: pcapkit.protocols.data.data

.. autoclass:: pcapkit.protocols.data.data.Data
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: __excluded__

      .. seealso::

         Please refer to :func:`Protocol._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
         for more information with the inserted names to be excluded.
