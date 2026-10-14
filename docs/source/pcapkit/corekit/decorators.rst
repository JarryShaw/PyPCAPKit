Decorator Functions
===================

.. module:: pcapkit.corekit.decorators

:mod:`pcapkit.corekit.decorators` contains several useful
decorators, including :func:`~pcapkit.corekit.decorators.seekset`,
:func:`~pcapkit.corekit.decorators.beholder` and
:func:`~pcapkit.corekit.decorators.prepare`.

.. note::

   This module was ``pcapkit.utilities.decorators`` until :issue:`1735` moved it
   here, and :mod:`pcapkit.utilities` no longer exports the three decorators.
   Nothing is left at the old path, so import them from this module.

.. autodecorator:: pcapkit.corekit.decorators.seekset

.. autodecorator:: pcapkit.corekit.decorators.beholder

.. autodecorator:: pcapkit.corekit.decorators.prepare

.. important::

   All three decorators above are designed for decorating *class methods*.
   For more information, please refer to the documentation of each
   decorator function.

Type Variables
--------------

.. data:: pcapkit.corekit.decorators.R_seekset
   :type: typing.Any

.. data:: pcapkit.corekit.decorators.R_beholder
   :type: pcapkit.protocols.protocol.ProtocolBase

.. data:: pcapkit.corekit.decorators.R_prepare
   :type: pcapkit.protocols.schema.schema.Schema
