Parsing Context
===============

.. Unlike its sibling pages, this one renders the module docstring through
   ``automodule`` rather than repeating it as prose. That docstring already
   carries its own ``.. module::`` directive -- as every module under
   ``pcapkit`` does -- so there must be no second one here, and ``automodule``
   itself must not register a third: hence ``:no-index:``.

.. automodule:: pcapkit.corekit.context
   :no-members:
   :no-index:

.. autoclass:: pcapkit.corekit.context.ProtocolContext
   :no-members:
   :show-inheritance:

   .. automethod:: protocol
   .. automethod:: __repr__

.. autoclass:: pcapkit.corekit.context.ContextRegistry
   :no-members:
   :show-inheritance:

   .. automethod:: register
   .. automethod:: make
   .. automethod:: match

   .. automethod:: __getitem__
   .. automethod:: __iter__
   .. automethod:: __len__
   .. automethod:: __contains__
   .. automethod:: __bool__
   .. automethod:: __repr__
