#!/bin/bash

# print a trace of simple commands
set -x

# duplicate distribution files
mkdir -p release
rm -rf release/src \
       release/pcapkit
cp -r src \
      LICENSE \
      setup.py \
      setup.cfg \
      .gitignore \
      README.md \
      MANIFEST.in \
      .gitattributes release/
cd release/
mv src pcapkit

# perform f2format
f2format -n src
ret="$?"
if [[ $ret -ne "0" ]] ; then
    exit $ret
fi

# prepare for PyPI distribution
mkdir eggs sdist wheels 2> /dev/null
rm -rf build 2> /dev/null
mv -f dist/*.egg eggs/ 2> /dev/null
mv -f dist/*.whl wheels/ 2> /dev/null
mv -f dist/*.tar.gz sdist/ 2> /dev/null

# distribute to PyPI and TestPyPI
python3 setup.py sdist
for python in /usr/local/Cellar/pypy/*/bin/pypy \
              /usr/local/Cellar/pypy3/*/bin/pypy3 \
              /usr/local/Cellar/python/*/bin/python3.? \
              /usr/local/Cellar/python@2/*/bin/python2.? ; do
            # /usr/bin/python \
            # /Library/Frameworks/Python.framework/Versions/?.?/bin/python?.? ; do
            # /System/Library/Frameworks/Python.framework/Versions/?.?/bin/python?.? ; do
    $python setup.py bdist_wheel
done
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
