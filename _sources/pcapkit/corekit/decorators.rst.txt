Decorator Functions
===================

.. module:: pcapkit.corekit.decorators

:mod:`pcapkit.corekit.decorators` contains several useful
decorators, including :func:`~pcapkit.corekit.decorators.seekset`,
:func:`~pcapkit.corekit.decorators.beholder` and
:func:`~pcapkit.corekit.decorators.prepare`.

.. versionadded:: 1.5.0

.. versionremoved:: 1.5.0

   ``pcapkit.utilities.decorators``, now :mod:`pcapkit.corekit.decorators`
   (:issue:`1735`). :mod:`pcapkit.utilities` does not export these
   decorators either.

.. autodecorator:: pcapkit.corekit.decorators.seekset

.. autodecorator:: pcapkit.corekit.decorators.beholder

.. autodecorator:: pcapkit.corekit.decorators.prepare

.. important::

   The decorators above are designed for decorating *methods*: an instance
   method of a protocol for :func:`seekset` and :func:`beholder`, and a
   classmethod of a schema for :func:`prepare`.
   For more information, please refer to the documentation of each
   decorator function.

Type Variables
--------------

.. data:: R_seekset
   :type: typing.Any

.. data:: R_beholder
   :type: pcapkit.protocols.protocol.ProtocolBase

.. data:: R_prepare
   :type: pcapkit.protocols.schema.schema.Schema
