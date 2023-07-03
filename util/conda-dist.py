# -*- coding: utf-8 -*-

import importlib.metadata as imp_meta
import os.path as os_path

import packaging.requirements as pkg_req

req_file = os_path.join('conda', 'requirements.txt')

data = {}  # dict[str, str]
with open(req_file) as file:
    for line in file:
        if not line.strip():
            continue
        req = pkg_req.Requirement(line)

        try:
            ver = imp_meta.version(req.name)
            if req.marker is None:
                data[req.name] = f'{req.name} == {ver}'
            else:
                data[req.name] = f'{req.name} == {ver} ; {req.marker}'
        except imp_meta.PackageNotFoundError:
            if req.marker is None:
                raise
            data[req.name] = f'{req.name} ; {req.marker}'

with open(req_file, 'w') as file:
    for key, line in sorted(data.items()):
        print(line, file=file)
