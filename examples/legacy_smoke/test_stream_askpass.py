# -*- coding: utf-8 -*-
"""Extract a live capture streamed from ``tcpdump``, with ``sudo -A``.

Same as :file:`test_stream.py`, but uses ``sudo -A`` so the password comes from the
``SUDO_ASKPASS`` helper rather than a terminal prompt. Still needs root, so it
cannot run unattended.

"""

import os
import shlex
import subprocess  # nosec: B404
import tempfile

import pcapkit

#: Interface to capture on. ``en0`` is macOS; on Linux this is usually ``eth0``
#: or ``wlan0`` -- see ``ip link`` or ``tcpdump -D``.
INTERFACE = 'en0'

# NOTE: buffer_path must not point inside ../captures/. That directory holds generated
# captures -- ../captures/stream.pcap among them -- which the runtime tests read and
# pin byte for byte, so buffering a live capture over it would quietly break the
# test suite. Buffer into a throwaway temporary file instead.
BUFFER = os.path.join(tempfile.mkdtemp(prefix='pcapkit-stream-'), 'stream.pcap')
print(f'buffering the live capture to {BUFFER}')

with subprocess.Popen(shlex.split(f'sudo -A tcpdump -i {INTERFACE} -s 0 -w - -U'),  # nosec: B603
                      stdout=subprocess.PIPE) as file:
    pcapkit.extract(fin=file.stdout, fout='../captures/stream.txt', format='tree', no_eof=True,
                    verbose=True, buffer_save=True, buffer_path=BUFFER)
