# -*- coding: utf-8 -*-

import os

import pkg_resources

req_file = os.path.join('conda', 'requirements.txt')

data = {}  # dict[str, tuple[str, str]]
with open(req_file) as file:
    req_map = pkg_resources.parse_requirements(file)
    for req in req_map:
        dist = pkg_resources.get_distribution(req.key)
        data[req.key] = (dist.version, req.marker)

with open(req_file, 'w') as file:
    for key, (version, marker) in sorted(data.items()):
        if marker is None:
            print(f'{key} == {version}', file=file)
        else:
            print(f'{key} == {version} ; {marker}', file=file)
