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
#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>
#include <xtt/util/file_io.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/asn1.h>

int xtt_generate_ecdsap256_keypair(const char *keypair_file)
{
    xtt_ecdsap256_pub_key pub = {.data = {0}};
    xtt_ecdsap256_priv_key priv  = {.data = {0}};

    // 1) Creat the ecdsa key pair
    int ret = xtt_crypto_create_ecdsap256_key_pair(&pub, &priv);
    if (0 != ret) {
        return KEY_CREATION_ERROR;
    }

    // 2) Create ASN.1 wrapped pair
    ret = xtt_write_ecdsap256_keypair(&pub, &priv, keypair_file);
    if (0 != ret) {
        return ret;
    }

    return 0;
}
