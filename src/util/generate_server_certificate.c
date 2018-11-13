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
#define _POSIX_C_SOURCE 200809L

#include <xtt/certificates.h>
#include <xtt/crypto_types.h>
#include <xtt/util/root.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/file_io.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

static
int create_expiry(const char* expiry_in, xtt_certificate_expiry* expiry) {
    if (NULL != expiry_in) {
        size_t max_check_len = sizeof(xtt_certificate_expiry) + 1; // +1 so strnlen return of max_check_len indicates error
        size_t expiry_in_len = strnlen(expiry_in, max_check_len);
        if (sizeof(xtt_certificate_expiry) != expiry_in_len) {
            return EXPIRY_PASSED;
        }
        memcpy(expiry->data, expiry_in, sizeof(xtt_certificate_expiry));
    } else {
        time_t today = time(NULL);
        struct tm* tm_today = gmtime(&today);
        int expiry_day = tm_today->tm_mday;
        int expiry_mon = tm_today->tm_mon + 1; // +1 because tm months are zero-indexed
        int expiry_year = tm_today->tm_year + 1900 + 1; // +1900 because tm years are 1900-indexed
        char temp_str[sizeof(xtt_certificate_expiry) + 1] = {0};
        int format_ret = snprintf(&temp_str[0], sizeof(temp_str), "%04d%02d%02d", expiry_year, expiry_mon, expiry_day);
        if (sizeof(xtt_certificate_expiry) != format_ret) {
            return EXPIRY_PASSED;
        }
        memcpy(expiry->data, temp_str, sizeof(xtt_certificate_expiry));
    }

    int ret = xtt_check_expiry(expiry);
    if(0 != ret){
        return EXPIRY_PASSED;
    }

    return 0;
}

int xtt_generate_server_certificate(const char* root_cert_file, const char* root_privatekey_file,
                                    const char* server_privatekey_file, const char* server_publickey_file,
                                    const char* server_id_file, const char* expiry_in,
                                    const char* server_certificate_filename)
{
    int read_ret = 0;
    int write_ret = 0;
    int ret = 0;

    // 1) Read in expiry, and check if it's valid; if no expiry is given, add one year from today
    xtt_certificate_expiry expiry = {.data = {0}};
    ret = create_expiry(expiry_in, &expiry);
    if (ret != 0) {
        return EXPIRY_PASSED;
    }

    // 2) Read root_certificate and private key from file
    xtt_root_certificate root_certificate = {.data = {0}};
    read_ret = xtt_read_from_file(root_cert_file, root_certificate.data, sizeof(xtt_root_certificate));
    if( read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    // 3) Read in root's public key, private key, and ID from certificate and ID file
    xtt_certificate_root_id root_id = {.data = {0}};
    xtt_ecdsap256_pub_key root_pub = {.data = {0}};
    xtt_ecdsap256_priv_key root_priv  = {.data = {0}};
    xtt_deserialize_root_certificate(&root_pub, &root_id, &root_certificate);

    read_ret = xtt_read_from_file(root_privatekey_file, root_priv.data, sizeof(xtt_ecdsap256_priv_key));
    if(read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    // 4) Read server id, public key and private key from files
    xtt_identity_type server_id = {.data = {0}};
    read_ret = xtt_read_from_file(server_id_file, server_id.data, sizeof(xtt_identity_type));
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }

    xtt_ecdsap256_pub_key server_public_key = {.data = {0}};
    xtt_ecdsap256_priv_key server_private_key = {.data = {0}};

    read_ret = xtt_read_from_file(server_publickey_file, server_public_key.data, sizeof(xtt_ecdsap256_pub_key));
    if(read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    read_ret = xtt_read_from_file(server_privatekey_file, server_private_key.data, sizeof(xtt_ecdsap256_priv_key));
    if (read_ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    // 5) Create server certificate and write it to file
    unsigned char serialized_certificate[XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH] = {0};
    xtt_return_code_type rc = 0;
    rc = xtt_generate_server_certificate_ecdsap256(serialized_certificate,
                                             &server_id,
                                             &server_public_key,
                                             &expiry,
                                             &root_id,
                                             &root_priv);
    if (XTT_RETURN_SUCCESS != rc) {
        return CERT_CREATION_ERROR;
    }

    write_ret = xtt_save_to_file(serialized_certificate, XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH, server_certificate_filename);
    if(write_ret < 0){
        return SAVE_TO_FILE_ERROR;
    }
    return 0;
}
