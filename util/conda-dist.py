# -*- coding: utf-8 -*-

import os
import sys
import pkg_resources
import subprocess  # nosec B404

req_file = os.path.join('conda', 'requirements.txt')

data = {}  # dict[str, str]
with open(req_file) as file:
    req_map = pkg_resources.parse_requirements(file)
    for req in req_map:
        dist = pkg_resources.get_distribution(req.key)
        data[req.key] = dist.version

with open(req_file, 'w') as file:
    for key, value in sorted(data.items()):
        print(f'{key}=={value}', file=file)

try:
    import pcapkit
    path = os.path.join(pcapkit.__path__[0], '_extern')
except ImportError:
    path = os.path.join('pcapkit', '_extern')
os.makedirs(path, exist_ok=True)

subprocess.check_call([  # nosec B603
    sys.executable, '-m', 'pip', 'install',
    '--target', path, '-r', req_file,
])
