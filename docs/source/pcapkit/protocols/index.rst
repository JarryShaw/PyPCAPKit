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

.. data:: pcapkit.protocols.__proto__
   :type: dict[str, Type[Protocol]]

   Protocol registry.

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

Data Model
----------

.. module:: pcapkit.protocols.data.data

.. autoclass:: pcapkit.protocols.data.data.Data
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autodata:: __excluded__
