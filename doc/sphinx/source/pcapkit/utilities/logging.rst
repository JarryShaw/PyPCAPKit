Logging System
==============

.. module:: pcapkit.utilities.logging

:mod:`pcapkit.utilities.logging` contains naïve integration
of the Python logging system, i.e. a :class:`logging.Logger`
instance as :data:`~pcapkit.utilities.logging.logger`.

.. autodata:: pcapkit.utilities.logging.logger
   :no-value:

.. autodata:: pcapkit.utilities.logging.DEVMODE
   :no-value:

   .. note::

      This variable can be configured through the environment variable
      :envvar:`PCAPKIT_DEVMODE`.
