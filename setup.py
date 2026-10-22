#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

# Python 2 only, not ``requires-python``'s 3.8 (#2051). pip builds the metadata
# with this file before it compares ``requires-python``, so a 3.8 guard here would
# replace pip's "requires a different Python" with a traceback. A Python 2 that
# runs this file directly would otherwise reach ``setup()`` with a setuptools too
# old to read ``pyproject.toml``.
if sys.version_info[0] <= 2:
    raise OSError("PyPCAPKit does not support Python 2!")

try:
    from setuptools import setup
except ImportError:
    raise ImportError("setuptools is required to install PyPCAPKit!")

# Everything is declared in ``pyproject.toml``. The long description is its
# static ``readme`` (#1968).
setup()
