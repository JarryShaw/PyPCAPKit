# -*- coding: utf-8 -*-
""":class:`Deferred` pickles under protocol 0 and 1 on GraalPy 25.4.

GitHub issue #2433, fixed by PR #2435.

Below protocol 2, :meth:`object.__reduce_ex__` hands the instance to
:func:`copyreg._reduce_ex`, whose MRO walk stops at the first non-heap base. On
CPython that is :class:`object`; on GraalPy :class:`~typing.Generic` is a
built-in type, so the walk calls ``Generic(self)`` and raises::

    TypeError: typing.Generic() takes no arguments

``Deferred`` reduces under protocol 0 and 1 as protocol 2 does, through
:class:`~pcapkit.utilities.pickle.ReduceAsProtocol2` (#2714), so the walk never
runs. GraalPy is not in this repository's regular environment, so
:class:`DeferredGraalPyPickleTests` patches :func:`copyreg._reduce_ex` to raise
the :exc:`TypeError` real GraalPy 25.4.4 raises.

:class:`DeferredSubclassReduceOverrideTests` pins that a subclass's own
``__reduce__`` is honoured at every protocol, which a hard-coded protocol 0/1
reduction drops.

"""

import copyreg
import pickle
import unittest
from unittest import mock

from pcapkit.foundation.reassembly.data.data import Deferred as _Deferred
from tests._support import reimport_once_per_class

#: Test tier (#1958): cross-interpreter pickling behaviour belongs on ``ALL``, as in
#: ``tests/foundation/reassembly/test_deferred_pickle_2423_unit.py``.
__tier__ = 'ALL'


def _analyze(proto: 'object', payload: 'bytes') -> 'tuple[object, bytes]':
    """Module-level stand-in analyser; picklable under every protocol."""
    return (proto, payload)


def _rebuild_reduce_override_sub(analyze: 'object', proto: 'object', payload: 'bytes',
                                  marker: 'object') -> '_ReduceOverrideSub':
    """Rebuild function of ``_ReduceOverrideSub.__reduce__``, module-level for :mod:`pickle`."""
    return _ReduceOverrideSub(analyze, proto, payload, marker)


class _ReduceOverrideSub(_Deferred):
    """A ``Deferred`` subclass overriding ``__reduce__``, module-level for :mod:`pickle`."""

    #: Set by ``__reduce__`` below; read back by the tests. A plain boolean
    #: rather than object identity, since the restored instance after a real
    #: pickle round trip is a brand-new object built by
    #: ``_rebuild_reduce_override_sub``, not ``self``.
    reduce_called = False

    def __init__(self, analyze: 'object', proto: 'object', payload: 'bytes',
                 marker: 'object') -> 'None':
        super().__init__(analyze, proto, payload)
        self.marker = marker

    def __reduce__(self) -> 'tuple[object, ...]':
        _ReduceOverrideSub.reduce_called = True
        return (_rebuild_reduce_override_sub,
                (self.analyze, self.proto, self.payload, self.marker))


class DeferredGraalPyPickleTests(unittest.TestCase):
    """Protocol 0 and 1 must not route through ``copyreg._reduce_ex`` at all.

    GraalPy fails inside that function, simulated here by making it raise the
    :exc:`TypeError` GraalPy does.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_protocol_0_1_survive_a_copyreg_reduce_ex_failure(self) -> None:
        """Protocol 0 and 1 round-trip while ``copyreg._reduce_ex`` raises GraalPy's error."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')

        def _raise_like_graalpy(self: 'object', proto: 'object') -> 'object':
            raise TypeError('typing.Generic() takes no arguments')

        with mock.patch.object(copyreg, '_reduce_ex', side_effect=_raise_like_graalpy):
            for protocol in (0, 1):
                with self.subTest(protocol=protocol):
                    restored = pickle.loads(pickle.dumps(deferred, protocol=protocol))
                    self.assertEqual(restored.proto, 42)
                    self.assertEqual(restored.payload, b'payload')
                    self.assertIs(restored.analyze, _analyze)

    def test_protocol_2_and_above_never_call_copyreg_reduce_ex(self) -> None:
        """Protocol 2 never calls ``copyreg._reduce_ex`` either.

        So the bypass above is specific to protocol 0 and 1, not a blanket detour.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        with mock.patch.object(copyreg, '_reduce_ex',
                                side_effect=AssertionError('must not be called')):
            restored = pickle.loads(pickle.dumps(deferred, protocol=2))
            self.assertEqual(restored.proto, 42)
            self.assertEqual(restored.payload, b'payload')


class DeferredSubclassReduceOverrideTests(unittest.TestCase):
    """A subclass's own ``__reduce__`` must be honoured at every protocol."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        _ReduceOverrideSub.reduce_called = False

    def test_override_is_called_under_every_protocol(self) -> None:
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                _ReduceOverrideSub.reduce_called = False
                sub = _ReduceOverrideSub(_analyze, 7, b'x', 'marker-value')
                restored = pickle.loads(pickle.dumps(sub, protocol=protocol))
                self.assertTrue(_ReduceOverrideSub.reduce_called,
                                f'__reduce__ override was bypassed at protocol {protocol}')
                self.assertIsInstance(restored, _ReduceOverrideSub)
                self.assertEqual(restored.proto, 7)
                self.assertEqual(restored.payload, b'x')
                self.assertEqual(restored.marker, 'marker-value')
                self.assertIs(restored.analyze, _analyze)


if __name__ == '__main__':
    unittest.main()
