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

if [[ $# -ne 3 ]]; then
        echo "usage: $0 <absolute-path-to-ecdaa-installation-directory> <absolute-path-to-xaptum-tpm-installation-directory> <absolute-path-to-amcl-installation-directory>"
        exit 1
fi

install_dir="$1"
xaptum_tpm_dir="$2"
amcl_dir="$3"
git clone https://github.com/xaptum/ecdaa "${install_dir}" 
pushd "${install_dir}" 
mkdir -p build
pushd build
cmake .. -DXAPTUM_TPM_LOCAL_DIR=${xaptum_tpm_dir} -DAMCL_LOCAL_DIR=${amcl_dir}
cmake --build .
popd
popd
