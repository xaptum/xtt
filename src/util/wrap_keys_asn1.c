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
#include <xtt/crypto_wrapper.h>
#include <xtt/util/asn1.h>
#include <xtt/util/file_io.h>
#include <xtt/util/util_errors.h>

int xtt_wrap_keys_asn1(const char *privkey_filename, const char *pubkey_filename, const char *asn1_filename)
{
    // 1) Read in key pair
    xtt_ecdsap256_pub_key pub = {.data = {0}};
    xtt_ecdsap256_priv_key priv = {.data = {0}};
    int read_ret = xtt_read_from_file(privkey_filename, priv.data, sizeof(xtt_ecdsap256_priv_key));
    if(read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    read_ret = xtt_read_from_file(pubkey_filename, pub.data, sizeof(xtt_ecdsap256_pub_key));
    if(read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    // 2) Create ASN.1 wrapped pair
    unsigned char asn1_priv_buf[XTT_ASN1_PRIVATE_KEY_LENGTH];
    int ret = xtt_asn1_from_ecdsap256_private_key(&priv, &pub, asn1_priv_buf, sizeof(asn1_priv_buf));
    if (0 != ret) {
        return ASN1_CREATION_ERROR;
    }

    // 3) Write wrapped key pair to file
    int write_ret = xtt_save_to_file(asn1_priv_buf, sizeof(asn1_priv_buf), asn1_filename);
    if (write_ret < 0) {
        return SAVE_TO_FILE_ERROR;
    }

    return 0;
}
