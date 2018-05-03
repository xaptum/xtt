#!/bin/bash
# Copyright 2017 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

set -e

if [[ $# -ne 1 ]]; then
        echo "usage: $0 <absolute-path-to-boost-source-directory>"
        exit 1
fi

echo "INSTALL_PREFIX=$INSTALL_PREFIX"
source_dir="$1"
mkdir -p ${source_dir}
pushd ${source_dir}
wget https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.gz
tar xfz boost_1_66_0.tar.gz
pushd boost_1_66_0
./bootstrap.sh --prefix=${INSTALL_PREFIX} --with-libraries=system,thread,coroutine,context
./b2 install variant=debug link=shared threading=multi -d0
popd
popd
