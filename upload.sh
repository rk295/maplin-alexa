#!/usr/bin/env bash

baseDir="/Users/robin/GIT/maplin-alexa"
zipName="rk-test.zip"
functionName="${zipName%%.zip}"

cd "$baseDir" || exit 1

aws --profile robin \
    lambda \
    update-function-code \
    --function-name "$functionName" \
    --zip-file fileb://"$zipName"
