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

#include "file_utils.h"

#include <xtt.h>

#include <stdio.h>
#include <string.h>

const char *root_id_file = "root_id.bin";
const char *root_pub_file = "root_pub.bin";
const char *root_priv_file = "root_priv.bin";

int main()
{
    int write_ret;
    int read_ret;

    // 0) Read root id from file
    xtt_certificate_root_id root_id;
    read_ret = read_file_into_buffer(root_id.data, sizeof(xtt_certificate_root_id), root_id_file);
    if (sizeof(xtt_certificate_root_id) != read_ret) {
        fprintf(stderr, "Error reading root's id from file\n");
        return 1;
    }

    // 1) Generate root's keypair
    xtt_ecdsap256_pub_key root_public_key;
    xtt_ecdsap256_priv_key root_priv_key;
    xtt_return_code_type rc = xtt_crypto_create_ecdsap256_key_pair(&root_public_key, &root_priv_key);
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error creating root's key pair\n");
        return 1;
    }

    // 2) Write root's public key to file
    write_ret = write_buffer_to_file(root_pub_file, root_public_key.data, sizeof(xtt_ecdsap256_pub_key));
    if (sizeof(xtt_ecdsap256_pub_key) != write_ret) {
        fprintf(stderr, "Error writing root's public key to file\n");
        return 1;
    }

    // 3) Write root's private key to file
    write_ret = write_buffer_to_file(root_priv_file, root_priv_key.data, sizeof(xtt_ecdsap256_priv_key));
    if (sizeof(xtt_ecdsap256_priv_key) != write_ret) {
        fprintf(stderr, "Error writing root's private key to file\n");
        return 1;
    }
}
