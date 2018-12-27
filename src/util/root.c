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
#include <string.h>
#include <xtt/crypto_types.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/util/root.h>
#include <xtt/util/file_io.h>
#include <xtt/util/util_errors.h>

void xtt_serialize_root_certificate(xtt_ecdsap256_pub_key *pub_key, xtt_certificate_root_id *root_id, xtt_root_certificate *info_out){
    memcpy(info_out->data, root_id->data, sizeof(xtt_certificate_root_id));
    memcpy(&info_out->data[sizeof(xtt_certificate_root_id)], pub_key->data, sizeof(xtt_ecdsap256_pub_key));
}

void xtt_deserialize_root_certificate(xtt_ecdsap256_pub_key *pub_key, xtt_certificate_root_id *root_id, xtt_root_certificate *root_cert_in) {
    memcpy(root_id->data, root_cert_in->data, sizeof(xtt_certificate_root_id));
    memcpy(pub_key->data, &root_cert_in->data[sizeof(xtt_certificate_root_id)], sizeof(xtt_ecdsap256_pub_key));
}

int xtt_generate_root(const char *pubkey_filename, const char *id_filename, const char *cert_filename)
{
    int read_ret = 0;
    // 1) Read root id from file, assigning root_id a random number if there is no file given
    xtt_certificate_root_id root_id = {.data = {0}};
    if (NULL != id_filename) {
        read_ret = xtt_read_from_file(id_filename, root_id.data, sizeof(xtt_certificate_root_id));
        if(read_ret < 0){
            return READ_FROM_FILE_ERROR;
        }
    } else
    {
        xtt_crypto_get_random(root_id.data, sizeof(xtt_certificate_root_id));
    }

    // 2) Get root's public key
    xtt_ecdsap256_pub_key pub = {.data = {0}};
    xtt_ecdsap256_priv_key priv = {.data = {0}};
    read_ret = xtt_read_ecdsap256_keypair(keypair_filename, &pub, &priv);
    if(read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    // 3) Create a root certificate out of public key and ID
    xtt_root_certificate root_certificate = {.data = {0}};
    xtt_serialize_root_certificate(&pub, &root_id, &root_certificate);

    // 4) Save info to files

    int write_ret = xtt_save_to_file(root_certificate.data, sizeof(xtt_root_certificate), cert_filename);
    if(write_ret < 0){
        return SAVE_TO_FILE_ERROR;
    }

    return 0;
}
