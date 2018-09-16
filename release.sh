#!/bin/bash


cp -r src release/src
cd release
mv archive/src archive/src-$( date +%y%m%d%H%M%S ) 2> /devnull
f2format src
if [[ "$?" -eq "0" ]] ; then
	pypi
	gitpush $1
fi
