#!/usr/bin/env bash

set -ex

# #3133: the pure-Python dependencies conda-forge lacks, which conda/requirements.txt pins.
$PYTHON -m pip install conda/wheels/* --target pcapkit/_extern --no-deps -vv
$PYTHON -m pip install . --no-deps -vv
