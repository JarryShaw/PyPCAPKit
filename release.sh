#!/bin/bash

set -x

cp -r src setup.py release/
cd release/

f2format src
if [[ "$?" -ne "0" ]] ; then
	exit 1
fi

pypi

git pull
git add .
if [[ -z $1 ]] ; then
	git commit -a
else
	git commit -a -m "$1"
fi
git push

for file in $( ls archive ) ; do
	if [[ -d "archive/${file}" ]] ; then
		tar -cvzf "archive/${file}.tar.gz" "archive/${file}"
		rm -rf "archive/${file}"
	fi
done
