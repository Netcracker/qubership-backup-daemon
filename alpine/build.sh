#!/usr/bin/env bash

cd $(dirname "$0")

echo "=> Remove artifacts from previous build..."

rm -rf ./src ./tests ./tools ./requirements.txt

echo "=> Copy source code and tests for run docker build..."

mkdir ./_build

cp -R ../src ./_build/src
cp -R ../tests ./_build/tests
cp -R ../tools ./_build/tools
cp ../requirements.txt ./_build/requirements.txt

docker build -t backup-daemon --no-cache .

for id in $DOCKER_NAMES; do
  docker tag backup-daemon "$id"
done
