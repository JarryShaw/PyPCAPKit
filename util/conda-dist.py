# -*- coding: utf-8 -*-

import os

import pkg_resources

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
