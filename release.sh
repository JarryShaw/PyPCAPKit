#!/bin/bash

# print a trace of simple commands
set -x

# duplicate distribution files
cp -r src setup.py release/
cd release/

# perform f2format
f2format src
if [[ "$?" -ne "0" ]] ; then
    exit 1
fi

# prepare for PyPI distribution
mkdir eggs sdist wheels 2> /dev/null
rm -rf build 2> /dev/null
mv -f dist/*.egg eggs/ 2> /dev/null
mv -f dist/*.whl wheels/ 2> /dev/null
mv -f dist/*.tar.gz sdist/ 2> /dev/null

# distribute to PyPI and TestPyPI
python3 setup.py sdist bdist_wheel
twine upload dist/* -r pypi --skip-existing
twine upload dist/* -r pypitest --skip-existing

# upload to GitHub
git pull
git add .
if [[ -z "$1" ]] ; then
    git commit -a
else
    git commit -a -m "$1"
fi
git push

# archive original files
for file in $( ls archive ) ; do
    if [[ -d "archive/${file}" ]] ; then
        tar -cvzf "archive/${file}.tar.gz" "archive/${file}"
        rm -rf "archive/${file}"
    fi
done

# upload develop environment
cd ..
git pull
git add .
if [[ -z "$1" ]] ; then
    git commit -a
else
    git commit -a -m "$1"
fi
git push
