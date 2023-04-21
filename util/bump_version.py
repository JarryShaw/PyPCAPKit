# -*- coding: utf-8 -*-

import os
import pkg_resources
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from packaging.version import Version

try:
    import pcapkit
    version = pcapkit.__version__
except ImportError:
    version = ''

    path = os.path.join('pcapkit', '__init__.py')
    with open(path, 'r', encoding='utf-8') as file:
        for line in file:
            if line.startswith('__version__'):
                version = line.split('=')[1].strip(" '")

    if not version:
        raise RuntimeError('cannot find version')

# parse version and bump version
ver_obj = pkg_resources.parse_version(version)  # type: Version
base_version = ver_obj.base_version

if ver_obj.is_devrelease:
    dev = cast('int', ver_obj.dev)
    new_ver = base_version + '.dev' + str(dev + 1)

elif ver_obj.is_prerelease:
    pre = cast('tuple[str, int]', ver_obj.pre)
    new_ver = base_version + pre[0] + str(pre[1] + 1)

elif ver_obj.is_postrelease:
    post = cast('int', ver_obj.post)
    new_ver = base_version + '.post' + str(post + 1)

else:
    new_ver = base_version + '.post1'

# write to file
with open('VERSION', 'w', encoding='utf-8') as file:
    file.write(str(new_ver))
