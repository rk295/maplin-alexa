#!/usr/bin/env bash

baseDir="/Users/robin/GIT/maplin-alexa"
zipName="rk-test.zip"
pythonSource="simple.py"

cd "$baseDir" || exit 1

echo "Removing old zip"
rm -f "$zipName"

echo "Adding site packages"
cd venv/lib/python2.7/site-packages/ || exit 1
zip -r9 "$baseDir/$zipName" .

echo "Adding $pythonSource"
cd "$baseDir" || exit 1
zip -r9 "$baseDir/$zipName" "$pythonSource"
