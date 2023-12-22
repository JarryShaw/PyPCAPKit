===================
Auxiliary Functions
===================

Decorators
==========

.. module:: pcapkit.utilities.decorators

:mod:`pcapkit.utilities.decorators` contains several useful
decorators, including :func:`~pcapkit.utilities.decorators.seekset`,
:func:`~pcapkit.utilities.decorators.beholder` and
:func:`~pcapkit.utilities.decorators.prepare`.

.. autodecorator:: pcapkit.utilities.decorators.seekset

.. autodecorator:: pcapkit.utilities.decorators.beholder

.. autodecorator:: pcapkit.utilities.decorators.prepare

.. important::

   All three decorators above are designed for decorating *class methods*.
   For more information, please refer to the documentation of each
   decorator function.

Type Variables
--------------

.. data:: pcapkit.utilities.decorators.R_seekset
   :type: typing.Any

.. data:: pcapkit.utilities.decorators.R_beholder
   :type: pcapkit.protocols.protocol.ProtocolBase

.. data:: pcapkit.utilities.decorators.R_prepare
   :type: pcapkit.protocols.schema.schmea.Schema

Error Handling Utilities
========================

.. autofunction:: pcapkit.utilities.exceptions.stacklevel

.. autofunction:: pcapkit.utilities.warnings.warn
