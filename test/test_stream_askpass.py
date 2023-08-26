# -*- coding: utf-8 -*-

import shlex
import subprocess  # nosec: B404

import pcapkit

with subprocess.Popen(shlex.split('sudo -A tcpdump -i en0 -s 0 -w - -U'),  # nosec: B603
                      stdout=subprocess.PIPE) as file:
    pcapkit.extract(fin=file.stdout, fout='../sample/stream.txt', format='tree', no_eof=True,
                    verbose=True, buffer_save=True, buffer_path='../sample/stream.pcap')
