/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include <xtt/crypto_types.h>

#include <stdio.h>

const xtt_identity_type xtt_null_identity = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

const xtt_certificate_root_id xtt_null_server_root_id = {{0}};

int
xtt_identity_to_string(const xtt_identity_type *identity_in,
                       xtt_identity_string *string_out)
{
    char *ptr = string_out->data;
    int k = 0;
    for (size_t i=0; i<sizeof(xtt_identity_type)+7; ++i) {
        if(0 == (i+1)%3){
            int encode_ret = sprintf(ptr, ":");
            if (encode_ret != 1) {
                return -1;
            }
            ptr ++;
        } else {
            int encode_ret = sprintf(ptr, "%02X", identity_in->data[k]);
            if (encode_ret != 2) {
                return -1;
            }
            ptr += 2;
            k++;
        }
    }

    string_out->data[sizeof(xtt_identity_string)-1] = 0;

    return 0;
}
