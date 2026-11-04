# -*- coding: utf-8 -*-
"""Threads making first imports at once all get what they asked for (GitHub issue #2771).

:func:`pcapkit.utilities.importlib.lazy_exports` imports a name the first time it is
reached, and :attr:`ModuleDescriptor.klass <pcapkit.corekit.module.ModuleDescriptor.klass>`
the module of a next layer, or of a :meth:`ProtocolBase.get_protocol
<pcapkit.protocols.protocol.ProtocolBase.get_protocol>` entry, the first time it is
resolved. Unserialised, two threads making such imports at once deadlock the import
system: InARP's protocol module imports ARP's ``data`` module, whose import lock is
taken before waiting on ARP's package, while a thread importing that package takes
the two the other way. So every such first import holds one re-entrant lock,
:data:`pcapkit.utilities.importlib.import_lock` (#2773 dropped the registry's own).

Each trial is a fresh interpreter, since the race only exists on a cold import, and
starts one thread per job behind a barrier. A thread that has not returned by
``DEADLINE`` counts as hung, which is how a lock that is not re-entrant fails: a
:mod:`pcapkit` name resolves through :mod:`pcapkit.protocols` and a layer package,
nesting lazy resolutions on one thread. Every name resolved must then be bound on its
package, so reaching it again never calls ``__getattr__`` and takes no lock. And every
first import of a :mod:`pcapkit` module a trial makes must hold the lock, so a path
that imports a module of its own accord fails on every run, not only on a lost race.

"""

import json
import os
import pathlib
import struct
import subprocess
import sys
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): races threads on the import system's locks, which differ between interpreters.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Fresh interpreters per test. Without the lock, measured per trial, nearly every one
#: deadlocked on CPython 3.14; on 3.12 about a third of the name races and few of the
#: dispatch races did, which the audit of unlocked first imports makes up for.
TRIALS = 4

#: Seconds a trial's threads have to finish before the rest count as hung.
DEADLINE = 60

#: The child: from a thread each, all at once, reach every unbound export of
#: ``packages``, every unbound submodule of ``submodules`` an export comes from, and
#: each of ``names``; parse each of ``frames`` from an Ethernet header; and look up
#: each protocol not imported yet with ``get_protocol`` if ``registry`` is set. Then
#: print what failed, hung, was left unbound, parsed or resolved to the wrong class,
#: or was imported for the first time without the lock held.
CHILD = '''
import importlib, io, json, os, sys, threading, time

spec = json.loads(sys.argv[1])
import pcapkit
assert pcapkit.__file__.startswith(spec['root']), pcapkit.__file__
from pcapkit.protocols.protocol import ProtocolBase
# A tree without the lock still runs, so that it fails on the race rather than on the import.
import_lock = getattr(importlib.import_module('pcapkit.utilities.importlib'), 'import_lock', None)
if spec['frames']:
    from pcapkit.protocols.link.ethernet.protocol import Ethernet

jobs = [('attr',) + tuple(target) for target in spec['names']]
for package in spec['packages']:
    module = importlib.import_module(package)
    jobs.extend(('attr', package, name) for name in module.__all__ if name not in vars(module))
for package in spec['submodules']:
    module = importlib.import_module(package)
    jobs.extend(('attr', package, name) for name in dir(module)
                if not name.startswith('__') and name not in module.__all__ and name not in vars(module))
for member, octets in spec['frames']:
    jobs.extend([('parse', member, octets)] * 3)
if spec['registry']:
    jobs.extend(('get', name, entry) for name, entry in ProtocolBase.__registry__.items()
                if entry.module not in sys.modules)
barrier = threading.Barrier(len(jobs))
errors, values, wrong, unlocked = [], {}, [], []


class Audit:
    """Note each first import of a :mod:`pcapkit` module made without the lock."""

    @staticmethod
    def find_spec(name, path=None, target=None):
        if name.startswith('pcapkit.') and import_lock is not None and not import_lock._is_owned():
            unlocked.append(name)


sys.meta_path.insert(0, Audit)


def run(kind, key, arg):
    if kind == 'attr':
        values[key, arg] = getattr(importlib.import_module(key), arg)
    elif kind == 'parse':
        layer, names = Ethernet(io.BytesIO(bytes.fromhex(arg)), len(arg) // 2), []
        for _ in range(8):
            names.append(type(layer).__name__)
            layer = layer.payload
        if key not in names:
            wrong.append(f'{key}: {names}')
    elif ProtocolBase.get_protocol(key) is not getattr(sys.modules[arg.module], arg.name):
        wrong.append(key)


def reach(*job):
    barrier.wait()
    try:
        run(*job)
    except BaseException as error:
        errors.append(f'{job[0]} {job[1]}: {error!r}')


threads = [threading.Thread(target=reach, args=job, name=f'{job[0]} {job[1]}', daemon=True) for job in jobs]
# Switching threads more often widens the race, which some interpreters lose rarely.
sys.setswitchinterval(1e-6)
for thread in threads:
    thread.start()
deadline = time.monotonic() + spec['deadline']
for thread in threads:
    thread.join(max(0, deadline - time.monotonic()))
hung = [thread.name for thread in threads if thread.is_alive()]
unbound = [f'{package}.{name}' for (package, name), value in list(values.items())
           if vars(sys.modules[package]).get(name) is not value]
print(json.dumps({'threads': len(jobs), 'errors': errors, 'hung': hung, 'unbound': unbound, 'wrong': wrong,
                  'unlocked': sorted(set(unlocked)), 'kinds': sorted({job[0] for job in jobs})}))
sys.stdout.flush()
# A hung thread holds import locks, which interpreter shutdown could wait on.
os._exit(0)
'''


def checksum(octets: 'bytes') -> 'bytes':
    """The Internet checksum of ``octets``."""
    octets += bytes(len(octets) % 2)
    total = sum(struct.unpack(f'>{len(octets) // 2}H', octets))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return struct.pack('>H', ~total & 0xffff)


def ipv4(proto: 'int', payload: 'bytes') -> 'bytes':
    """An IPv4 header from 10.0.0.1 to 224.0.0.1, with its checksum, carrying ``payload``."""
    head = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                       bytes([10, 0, 0, 1]), bytes([224, 0, 0, 1]))
    return head[:10] + checksum(head) + head[12:] + payload


def igmp(kind: 'int', rest: 'bytes' = bytes(4)) -> 'bytes':
    """An IGMP message of type ``kind``, with its checksum."""
    body = bytes([kind, 0, 0, 0]) + rest
    return body[:2] + checksum(body) + body[4:]


def ether(kind: 'int', body: 'bytes') -> 'bytes':
    """An Ethernet frame of EtherType ``kind``."""
    return bytes([0xff] * 6) + bytes(range(6)) + struct.pack('>H', kind) + body


def arp(operation: 'int') -> 'bytes':
    """An ARP message of ``operation``, for IPv4 over Ethernet, its addresses zero."""
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, operation) + bytes(20)


def udp(port: 'int', payload: 'bytes' = b'') -> 'bytes':
    """A UDP datagram from port 1701 to ``port``."""
    return struct.pack('>HHHH', 1701, port, 8 + len(payload), 0) + payload


#: A frame per family member, each of which its first parse dispatches to: the
#: member's own module imports its base's.
FRAMES = [
    ('ARP', ether(0x0806, arp(1))),
    ('RARP', ether(0x8035, arp(3))),
    ('C_Tag', ether(0x8100, bytes([0, 1, 0x08, 0]) + ipv4(17, udp(53)))),
    ('S_Tag', ether(0x88a8, bytes([0, 1, 0x08, 0]) + ipv4(17, udp(53)))),
    ('IGMPv1', ether(0x0800, ipv4(2, igmp(0x12)))),
    ('IGMPv2', ether(0x0800, ipv4(2, igmp(0x16)))),
    ('IGMPv3', ether(0x0800, ipv4(2, igmp(0x22)))),
    ('L2TPv2', ether(0x0800, ipv4(17, udp(1701, struct.pack('>HHH', 0x0002, 1, 1))))),
]


def run_trial(packages: 'list[str]', submodules: 'list[str]', names: 'tuple[tuple[str, str], ...]' = (), *,
              frames: 'bool' = False, registry: 'bool' = False) -> 'dict[str, Any]':
    """Run :data:`CHILD` in a fresh interpreter; return what it printed."""
    environ = dict(os.environ)
    environ.pop('PYTHONSAFEPATH', None)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
    spec = json.dumps({'root': str(ROOT), 'packages': packages, 'submodules': submodules, 'names': names,
                       'frames': [(member, octets.hex()) for member, octets in FRAMES] if frames else [],
                       'registry': registry, 'deadline': DEADLINE})
    result = subprocess.run([sys.executable, '-c', CHILD, spec],  # nosec: B603
                            cwd=str(ROOT), env=environ, capture_output=True, text=True,
                            timeout=DEADLINE + 240, check=False)
    if result.returncode != 0:
        raise AssertionError(f'child exited {result.returncode}:\n{result.stderr}')
    return json.loads(result.stdout.splitlines()[-1])


class ConcurrentFirstImportTests(unittest.TestCase):
    """Every job run from many threads at once, on a cold import, gets what it asked for."""

    def check(self, *args: 'Any', **kwargs: 'Any') -> 'list[dict[str, Any]]':
        """Run :data:`TRIALS` trials of :data:`CHILD`; fail on one where a job went wrong."""
        outs = [run_trial(*args, **kwargs) for _ in range(TRIALS)]
        keys = ('errors', 'hung', 'unbound', 'wrong', 'unlocked')
        failed = [{key: out[key][:3] for key in keys if out[key]} for out in outs if any(out[key] for key in keys)]
        if failed:
            self.fail(f'{len(failed)} of {TRIALS} trials failed; first: {failed[0]}')
        for out in outs:
            self.assertGreaterEqual(out['threads'], 16)
        return outs

    def test_threads_reaching_different_names_resolve_them_all(self) -> 'None':
        """:mod:`pcapkit.protocols`, two layer packages and two const packages, all at once."""
        self.check(['pcapkit.protocols', 'pcapkit.protocols.link',
                    'pcapkit.const.ipv4', 'pcapkit.const.ipv6'], ['pcapkit.protocols.internet'])

    def test_a_resolution_nesting_another_package_resolves(self) -> 'None':
        """A :mod:`pcapkit` name nests the resolutions of :mod:`pcapkit.protocols` and a layer package."""
        self.check(['pcapkit'], [])

    def test_threads_dispatching_to_different_family_members_parse_them(self) -> 'None':
        """Each frame's first parse imports a family member, through its next-layer descriptor."""
        self.check([], [], frames=True)

    def test_get_protocol_racing_first_dispatches_resolves_every_name(self) -> 'None':
        """Every protocol not imported yet, InARP and DRARP among them, looked up as frames dispatch."""
        outs = self.check([], [], frames=True, registry=True)
        for out in outs:
            self.assertEqual(out['kinds'], ['get', 'parse'])


if __name__ == '__main__':
    unittest.main()
