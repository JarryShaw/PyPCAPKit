Info Class
==========

.. module:: pcapkit.corekit.infoclass

:mod:`pcapkit.corekit.infoclass` contains :obj:`dict` like class
:class:`~pcapkit.corekit.infoclass.Info` only, which is originally
designed to work alike :func:`dataclasses.dataclass` as introduced
in :pep:`557`.

.. autoclass:: pcapkit.corekit.infoclass.Info
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: __additional__
      :no-value:
   .. autoattribute:: __excluded__
      :no-value:
