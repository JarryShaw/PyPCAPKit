#!/usr/bin/env bash

set -x

# change CWD
cd /pypcapkit

# set alias
alias pypy3="PYTHONPATH=/usr/local/lib/pypy3.5/dist-packages pypy3"

# make Python >=3.6 distribution
python3.7 setup.py sdist bdist_egg bdist_wheel --plat-name="manylinux1_x86_64" --python-tag='cp37' && \
python3.6 setup.py bdist_egg bdist_wheel --plat-name="manylinux1_x86_64" --python-tag='cp36'
returncode="$?"
if [[ ${returncode} -ne "0" ]] ; then
    exit ${returncode}
fi

# perform f2format
f2format -n /pypcapkit/pcapkit
returncode="$?"
if [[ ${returncode} -ne "0" ]] ; then
    exit ${returncode}
fi

# make Python <3.6 distribution
python3.5 setup.py bdist_egg bdist_wheel --plat-name="manylinux1_x86_64" --python-tag='cp35' && \
python3.4 setup.py bdist_egg bdist_wheel --plat-name="manylinux1_x86_64" --python-tag='cp34' && \
pypy3 setup.py bdist_wheel --plat-name="manylinux1_x86_64" --python-tag='pp35'
returncode="$?"
if [[ ${returncode} -ne "0" ]] ; then
    exit ${returncode}
fi
