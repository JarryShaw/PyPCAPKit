#!/usr/bin/env bash

# print a trace of simple commands
set -x

# update const scripts
for file in src/vendor/*/*.py ; do
    pipenv run python3 $file
done

# duplicate distribution files
mkdir -p release
rm -rf release/src \
       release/pcapkit
cp -rf src \
       LICENSE \
       setup.py \
       setup.cfg \
       .gitignore \
       README.md \
       MANIFEST.in \
       .gitattributes release/
rm -rf release/src/protocols/*/NotImplemented \
       release/**/__pycache__ \
       release/**/.DS_Store
cd release/
mv src pcapkit

# prepare for PyPI distribution
mkdir eggs sdist wheels 2> /dev/null
rm -rf build 2> /dev/null
mv -f dist/*.egg eggs/ 2> /dev/null
mv -f dist/*.whl wheels/ 2> /dev/null
mv -f dist/*.tar.gz sdist/ 2> /dev/null
rm -rf dist 2> /dev/null

# fetch platform spec
platform=$( python3 -c "import distutils.util; print(distutils.util.get_platform().replace('-', '_').replace('.', '_'))" )

# make Python >=3.6 distribution
python3.7 setup.py bdist_egg bdist_wheel --plat-name="${platform}" --python-tag='cp37'
python3.6 setup.py bdist_egg bdist_wheel --plat-name="${platform}" --python-tag='cp36'

# perform f2format
f2format -n pcapkit
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi

# make Python <3.6 distribution
# for python in /usr/bin/python \
#               /usr/local/Cellar/pypy/*/bin/pypy \
#               /usr/local/Cellar/pypy3/*/bin/pypy3 \
#               /usr/local/Cellar/python/*/bin/python3.? \
#               /usr/local/Cellar/python@2/*/bin/python2.? \
#               /Library/Frameworks/Python.framework/Versions/?.?/bin/python?.?
#               /System/Library/Frameworks/Python.framework/Versions/?.?/bin/python?.? ; do
#     $python setup.py bdist_egg
# done
python3.5 setup.py bdist_egg bdist_wheel --plat-name="${platform}" --python-tag='cp35'
python3.4 setup.py bdist_egg bdist_wheel --plat-name="${platform}" --python-tag='cp34'
pypy3 setup.py bdist_wheel --plat-name="${platform}" --python-tag='pp35'
python3 setup.py sdist

# distribute to PyPI and TestPyPI
twine upload dist/* -r pypi --skip-existing
twine upload dist/* -r pypitest --skip-existing

# get version string
version=$( cat setup.py | grep "^__version__" | sed "s/__version__ = '\(.*\)'/\1/" )

# upload to GitHub
git pull && \
git tag "v${version}" && \
git add . && \
if [[ -z "$1" ]] ; then
    git commit -a -S
else
    git commit -a -S -m "$1"
fi && \
git push
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi

# # archive original files
# for file in $( ls archive ) ; do
#     if [[ -d "archive/${file}" ]] ; then
#         tar -cvzf "archive/${file}.tar.gz" "archive/${file}"
#         rm -rf "archive/${file}"
#     fi
# done

# upload develop environment
cd ..
git pull && \
git tag "v${version}" && \
git add . && \
if [[ -z "$1" ]] ; then
    git commit -a -S
else
    git commit -a -S -m "$1"
fi && \
git push
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi

# file new release
go run github.com/aktau/github-release release \
    --user JarryShaw \
    --repo PyPCAPKit \
    --tag "v${version}" \
    --name "PyPCAPKit v${version}" \
    --description "$1"
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi

# update maintenance information
cd ..
maintainer changelog && \
maintainer contributor && \
maintainer contributing
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi

# aftermath
git pull && \
git add . && \
git commit -a -S -m "Regular update after distribution" && \
git push
