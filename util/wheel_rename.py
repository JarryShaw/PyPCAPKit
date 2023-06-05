# -*- coding: utf-8 -*-

import os
import shutil
import sys
import warnings

# python implementation
MAP_IMPL = {
    'cpython': 'cp',
    'pypy': 'pp',
}
implementation = MAP_IMPL.get(sys.implementation.name)
if implementation is None:
    raise ValueError(f'Unknown Python implementation: {sys.implementation.name}')
python = f'{implementation}%s%s' % sys.version_info[:2]

for file in sys.argv[1:]:
    root, name = os.path.split(file)
    if not name.endswith('.whl'):
        continue

    # wheel name format
    # {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
    try:
        distribution, version, _, abi, platform = os.path.splitext(name)[0].split('-')
    except ValueError:
        warnings.warn(f'Unknown filename: {name}')
        continue

    if distribution != 'pypcapkit':
        warnings.warn(f'Unknown distribution: {distribution}')
        continue

    new_file = f'pypcapkit-{version}-{python}-{abi}-{platform}.whl'
    shutil.move(file, os.path.join(root, new_file))
