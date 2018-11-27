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

#include <xtt/certificates.h>
#include <xtt/crypto_types.h>
#include <xtt/util/file_io.h>
#include <xtt/util/generate_server_certificate.h>
#include <xtt/util/root.h>
#include <xtt/util/util_errors.h>

// To allow deployed Xaptum clients (which may still be checking server id and expiry)
// to continue accepting new certificates,
// just use the following as the default "reserved" field for now.
// This corresponds, in the old schema of server certificates,
// to a server-id of "XAPTUMSERVER0001"
// and an expiry of 9999-12-31 (December 31 in the year 9999).
// These bytes are simply ignored by newer clients.
const xtt_certificate_reserved reserved_default = {.data="XAPTUMSERVER000199991231"};

int xtt_generate_server_certificate(const char* root_cert_file, const char* root_privatekey_file,
                                    const char* reserved_file,
                                    const char* server_privatekey_file, const char* server_publickey_file,
                                    const char* server_certificate_filename)
{
    int read_ret = 0;
    int write_ret = 0;

    // 1) Read reserved field in from file, assigning the default if there is no file given
    xtt_certificate_reserved reserved = {.data = {0}};
    if (NULL != reserved_file) {
        read_ret = xtt_read_from_file(reserved_file, reserved.data, sizeof(xtt_certificate_reserved));
        if(read_ret < 0){
            return READ_FROM_FILE_ERROR;
        }
    } else {
        reserved = reserved_default;
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

    // 4) Read server public key and private key from files
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
                                             &reserved,
                                             &server_public_key,
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
