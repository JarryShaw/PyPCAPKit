# -*- coding: utf-8 -*-
"""A reassembled TCP datagram pickles while its ``packet`` is still deferred.

GitHub issue :issue:`2417`. Dispatching on
:class:`~pcapkit.const.reg.apptype.apptype.AppType` members rather than bare
port numbers put those members inside the
:class:`~pcapkit.foundation.reassembly.data.data.Deferred` that
:meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` stores as a
:class:`~pcapkit.foundation.reassembly.data.tcp.Datagram`'s ``packet``. For a
port the registry holds no assignment for, such a member was absent from the
value table ``Enum.__reduce_ex__`` reduces to, so the datagram pickled and then
raised on read-back::

    ValueError: 'unknown [50000 - tcp]' is not a valid TCP

which is 90.7% of the port space and therefore most real captures -- client
sockets are ephemeral. :meth:`EnumRegistry._make_reducible
<pcapkit.corekit.enum.EnumRegistry._make_reducible>` fixes the member itself;
:mod:`tests.const.test_const_apptype_unregistered_pickle_2417_unit` pins that
over the whole port space. These synthesise the datagram directly, on both an
unassigned and an assigned flow, rather than reading a capture --
:mod:`tests.foundation.reassembly.test_datagram_deferred_pickle_2417_runtime`
pins the same thing end to end over the sample captures, which is how the bug
was originally found: a datagram is only worth pickling *while* its payload is
unresolved, so the failure sat exactly where nothing else would catch it.

Pickled before :attr:`~...Datagram.packet` is read, deliberately: reading it
resolves the :class:`Deferred` through
:meth:`DeferredPacket.__analyse__ <pcapkit.corekit.packet.DeferredPacket.__analyse__>`
and replaces the placeholder, so a datagram whose packet has been touched no
longer holds the members this is about.

"""
from __future__ import annotations

import pickle
import unittest
from ipaddress import ip_address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'

#: Pickle protocols a whole :class:`Deferred` can go through.
#:
#: Protocols ``0`` and ``1`` are excluded, and not because of anything
#: :issue:`2417` changed: :class:`~pcapkit.foundation.reassembly.data.data.Deferred`
#: declares ``__slots__`` and no ``__getstate__``, which those two protocols
#: cannot serialise at all -- ``TypeError: a class that defines __slots__
#: without defining __getstate__ cannot be pickled``, raised from
#: :mod:`copyreg`. Measured on CPython 3.14.10 to be independent of the ports:
#: it reproduces for an assigned flow, for an unassigned one, and for a bare
#: ``Deferred(..., 42, b'x')`` holding a plain :obj:`int`, while ``2``-``5``
#: pass in every one of those cases. That is a separate limitation of the class,
#: not of the members it holds, which is why it is scoped out here rather than
#: worked around; the member-level round trip is pinned on *every* protocol from
#: ``0`` up in :mod:`tests.const.test_const_apptype_unregistered_pickle_2417_unit`.
PROTOCOLS = tuple(range(2, pickle.HIGHEST_PROTOCOL + 1))

#: A flow on two unassigned ports, which is what used to fail.
UNASSIGNED_BUFID = (ip_address('192.0.2.1'), 50000, ip_address('198.51.100.2'), 65535)

#: The same shape on two IANA assignments, which always worked.
ASSIGNED_BUFID = (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)


def _held(datagram: 'Any') -> 'Any':
    """``datagram``'s unresolved ``packet`` placeholder, without resolving it."""
    key = datagram.__map__.get('packet', 'packet')
    return datagram.__dict__[key]


def _datagram(bufid: 'Any') -> 'Any':
    """One complete TCP datagram under ``bufid``, its ``packet`` still deferred.

    A single segment carrying FIN, which closes the stream and so submits it
    complete -- the partial branch of ``submit`` reports ``packet=None`` and
    builds no :class:`Deferred` at all.

    """
    from pcapkit.foundation.reassembly.data.tcp import Packet
    from pcapkit.foundation.reassembly.tcp import TCP

    reasm = TCP()
    reasm(Packet(bufid, 1, 500, 1, False, True, False, 5, 1, 5,
                 b'', bytearray(b'hello'), 1000.0))
    datagram, = reasm.datagram
    return datagram


class DeferredDatagramPickleTests(unittest.TestCase):
    """A synthesised datagram, on assigned and unassigned ports alike."""

    def test_an_unassigned_flow_round_trips(self) -> None:
        """The case that failed: both ports resolve to unregistered members."""
        from pcapkit.const.reg.apptype.tcp import TCP as AppType_TCP

        datagram = _datagram(UNASSIGNED_BUFID)
        ports = _held(datagram).proto
        self.assertEqual([port.name for port in ports], ['unknown', 'unknown'])

        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                restored = pickle.loads(pickle.dumps(datagram, protocol))
                restored_ports = _held(restored).proto

                self.assertEqual(restored_ports, ports)
                for port in restored_ports:
                    self.assertIsInstance(port, AppType_TCP)
                self.assertEqual([port.port for port in restored_ports],
                                 [UNASSIGNED_BUFID[1], UNASSIGNED_BUFID[3]])
                self.assertEqual(bytes(restored.payload), bytes(datagram.payload))

    def test_an_assigned_flow_round_trips(self) -> None:
        """The control: registered members were never broken, and still are not."""
        datagram = _datagram(ASSIGNED_BUFID)
        ports = _held(datagram).proto

        restored_ports = _held(pickle.loads(pickle.dumps(datagram))).proto

        self.assertEqual(restored_ports, ports)
        self.assertEqual([port.svc for port in restored_ports], ['italk', 'https'])

    def test_the_packet_still_resolves_after_a_round_trip(self) -> None:
        """A restored datagram is still usable, not merely loadable.

        The members come back unregistered, so this also pins that
        :meth:`Transport.analyze
        <pcapkit.protocols.transport.transport.Transport.analyze>` can still key
        :attr:`TCP.__proto__
        <pcapkit.protocols.transport.transport.Transport.__proto__>` with one --
        which is what :meth:`AppType.__hash__
        <pcapkit.const.reg.apptype.apptype.AppType.__hash__>` being its port's
        buys.

        """
        from pcapkit.protocols.protocol import ProtocolBase

        restored = pickle.loads(pickle.dumps(_datagram(UNASSIGNED_BUFID)))

        self.assertIsInstance(restored.packet, ProtocolBase)


if __name__ == '__main__':
    unittest.main()
