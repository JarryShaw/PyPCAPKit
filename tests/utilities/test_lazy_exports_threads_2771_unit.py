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
import tempfile
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
#: each of ``names``; parse each of ``frames`` from an Ethernet header; look up each
#: protocol not imported yet with ``get_protocol`` if ``registry`` is set; and, given a
#: ``capture``, make each of its ``calls``. Then print what failed, hung, was left
#: unbound, parsed or resolved to the wrong class, or was imported for the first time
#: without the lock held.
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

calls = {}
if spec['capture']:
    # NOTE: imported first without the lock on purpose: its package imports nothing
    # from pcapkit.protocols, so no import-lock cycle runs through it.
    import pcapkit.corekit.checksum.internet
    from pcapkit.protocols.application.http.protocol import HTTP
    from pcapkit.protocols.internet.ipv4.protocol import IPv4
    from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
    from pcapkit.protocols.transport.udp.protocol import UDP
    from pcapkit.utilities.exceptions import ProtocolError

    def from_data():
        try:
            HTTP.from_data(object())
        except ProtocolError:
            return
        raise AssertionError('HTTP.from_data took an object')

    calls = {
        'members': lambda: [LinuxSLL._member_of_version(1), LinuxSLL._member_of_version(2),
                            ProtocolBase.get_protocol('L2TP')._member_of_version(2)],
        'from_data': from_data,
        'index': lambda: [ProtocolBase.get_protocol(name).__index__()
                          for name in ('DTLS', 'FTP', 'FTP_DATA', 'HTTP', 'TLS', 'L2TPv2')],
        'compute': lambda: IPv4(src='10.0.0.1', dst='10.0.0.2', protocol=17,
                                payload=UDP(srcport=1, dstport=2, payload=b'ab')),
        'extract': lambda: pcapkit.extract(fin=spec['capture'], nofile=True, reassembly=True,
                                           verbose=False),
    }

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
for name in calls:
    jobs.extend([('call', name, None)] * 2)
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
    elif kind == 'call':
        calls[key]()
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

#: A frame per helper its first parse resolves with checksums verified: HTTP's member
#: for an HTTP/1.1 request, and the pseudo-header check over TCP, over UDP, and past
#: an Authentication Header.
HELPER_FRAMES = [
    ('HTTPv1', ether(0x0800, ipv4(6, struct.pack('>HHIIBBHHH', 1234, 80, 1, 0, 5 << 4, 0x18, 1024, 0, 0)
                                  + b'GET / HTTP/1.1\r\nHost: a\r\n\r\n'))),
    ('AH', ether(0x0800, ipv4(51, bytes([17, 1, 0, 0]) + struct.pack('>II', 1, 1) + udp(53)))),
    ('UDP', ether(0x0800, ipv4(17, udp(53, b'abcd')))),
]


def run_trial(packages: 'list[str]', submodules: 'list[str]', names: 'tuple[tuple[str, str], ...]' = (), *,
              frames: 'bool' = False, registry: 'bool' = False, capture: 'str' = '') -> 'dict[str, Any]':
    """Run :data:`CHILD` in a fresh interpreter; return what it printed.

    With a ``capture``, the frames are :data:`HELPER_FRAMES`, parsed with checksums
    verified, and the calls are made, one of which extracts ``capture``.

    """
    environ = dict(os.environ)
    environ.pop('PYTHONSAFEPATH', None)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
    if capture:
        environ['PCAPKIT_CHECKSUM_VERIFY'] = '1'
    chosen = HELPER_FRAMES if capture else FRAMES if frames else []
    spec = json.dumps({'root': str(ROOT), 'packages': packages, 'submodules': submodules, 'names': names,
                       'frames': [(member, octets.hex()) for member, octets in chosen],
                       'registry': registry, 'capture': capture, 'deadline': DEADLINE})
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

    def test_member_and_helper_first_imports_hold_the_lock(self) -> 'None':
        """Members, data models, port registries, checksum helpers and toolkit, each first resolved at once."""
        with tempfile.TemporaryDirectory() as directory:
            capture = os.path.join(directory, 'helpers.pcap')
            with open(capture, 'wb') as file:
                file.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                for _, octets in HELPER_FRAMES:
                    file.write(struct.pack('<IIII', 0, 0, len(octets), len(octets)) + octets)
            outs = self.check([], [], capture=capture)
        for out in outs:
            self.assertEqual(out['kinds'], ['call', 'parse'])


if __name__ == '__main__':
    unittest.main()
