# -*- coding: utf-8 -*-

import os

build_path = os.path.join('conda', 'build')

with open(build_path, 'r') as file:
    temp = file.readline()
    build = int(temp.strip())

with open(build_path, 'w') as file:
    file.write(str(build + 1))
