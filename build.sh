#!/bin/bash

mkdir -p out
pushd out
cmake .. -DCMAKE_TOOLCHAIN_FILE=/Users/john/code/vcpkg/scripts/buildsystems/vcpkg.cmake 
make

popd
