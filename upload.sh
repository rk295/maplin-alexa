#!/usr/bin/env bash

#
# Hacky script to upload a Lambda zip file to your AWS account. The name of the
# Lambda function is taken from the name of the zip, without the `.zip` suffix.
#
# Optionally looks for the following environment variables:
#
# * ZIP_NAME        - Name of the zip file to create, defaults to 'rk-test.zip'.
# * AWS_PROFILE     - Name of the awscli profile to use, defaults to 'robin'.
#
set -euo pipefail

cd "${0%/*}" || exit 1
baseDir=$(pwd)

: ${ZIP_NAME:="rk-test.zip"}
: ${AWS_PROFILE:="robin"}

functionName="${ZIP_NAME%%.zip}"

aws --profile "$AWS_PROFILE" \
    lambda \
    update-function-code \
    --function-name "$functionName" \
    --zip-file fileb://"$ZIP_NAME"
