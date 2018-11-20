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
rm -rf release/**/.DS_Store
cd release/
mv src pcapkit

# prepare for PyPI distribution
mkdir eggs sdist wheels 2> /dev/null
rm -rf build 2> /dev/null
mv -f dist/*.egg eggs/ 2> /dev/null
mv -f dist/*.whl wheels/ 2> /dev/null
mv -f dist/*.tar.gz sdist/ 2> /dev/null

# make Python >=3.6 distribution
python3 setup.py sdist bdist_egg bdist_wheel
file=$( ls dist/*.tar.gz )
name=${file%*.tar.gz*}
cp "${name}-py3-none-any.whl" "${name}-py37-none-any.whl"
cp "${name}-py3-none-any.whl" "${name}-py36-none-any.whl"
mv "${name}-py3.7.egg" "${name}-py3.6.egg"
rm dist/*.tar.gz "${name}-py3-none-any.whl"

# perform f2format
f2format -n src
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
python3 setup.py sdist bdist_egg bdist_wheel
cp "${name}-py3-none-any.whl" "${name}-py35-none-any.whl"
cp "${name}-py3-none-any.whl" "${name}-py34-none-any.whl"
cp "${name}-py3.7.egg" "${name}-py3.5.egg"
cp "${name}-py3.7.egg" "${name}-py3.4.egg"
cp "${name}-py3.6.egg" "${name}-py3.7.egg"
rm "${name}-py3-none-any.whl"

# distribute to PyPI and TestPyPI
twine upload dist/* -r pypi --skip-existing
twine upload dist/* -r pypitest --skip-existing

# upload to GitHub
git pull
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi
git add .
if [[ -z "$1" ]] ; then
    git commit -a -S
else
    git commit -a -S -m "$1"
fi
git push

# # archive original files
# for file in $( ls archive ) ; do
#     if [[ -d "archive/${file}" ]] ; then
#         tar -cvzf "archive/${file}.tar.gz" "archive/${file}"
#         rm -rf "archive/${file}"
#     fi
# done

# upload develop environment
cd ..
git pull
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi
git add .
if [[ -z "$1" ]] ; then
    git commit -a -S
else
    git commit -a -S -m "$1"
fi
git push
