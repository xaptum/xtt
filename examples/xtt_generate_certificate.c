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

const char *server_id_file = "server_id.bin";
const char *root_id_file = "root_id.bin";
const char *root_pub_file = "root_pub.bin";
const char *root_priv_file = "root_priv.bin";
const char *server_privatekey_file = "server_privatekey.bin";
const char *server_certificate_file = "server_certificate.bin";

const unsigned char *expiry_str = (unsigned char*)"21001231";   // Dec 31, 2100

int main()
{
    (void)write_buffer_to_file;

    int read_ret;

    // 0) Set server's id from file
    xtt_identity_type server_id;
    read_ret = read_file_into_buffer(server_id.data, sizeof(xtt_identity_type), server_id_file);
    if (sizeof(xtt_identity_type) != read_ret) {
        fprintf(stderr, "Error reading server's ID from file\n");
        return -1;
    }

    // 1) Read root's info in from files.
    xtt_certificate_root_id root_id;
    read_ret = read_file_into_buffer(root_id.data, sizeof(xtt_certificate_root_id), root_id_file);
    if (sizeof(xtt_certificate_root_id) != read_ret) {
        fprintf(stderr, "Error reading root's id from file\n");
        return 1;
    }

    xtt_ed25519_pub_key root_public_key;
    read_ret = read_file_into_buffer(root_public_key.data, sizeof(xtt_ed25519_pub_key), root_pub_file);
    if (sizeof(xtt_ed25519_pub_key) != read_ret) {
        fprintf(stderr, "Error reading root's public key from file\n");
        return 1;
    }
    xtt_ed25519_priv_key root_priv_key;
    read_ret = read_file_into_buffer(root_priv_key.data, sizeof(xtt_ed25519_priv_key), root_priv_file);
    if (sizeof(xtt_ed25519_priv_key) != read_ret) {
        fprintf(stderr, "Error reading root's private key from file\n");
        return 1;
    }

    // 2) Generate keypair and certificat for server
    xtt_ed25519_pub_key public_key;
    xtt_ed25519_priv_key server_private_key;
    xtt_return_code_type rc;
    rc = xtt_crypto_create_ed25519_key_pair(&public_key, &server_private_key);
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error creating server's key pair\n");
        return 1;
    }

    xtt_certificate_expiry expiry;
    memcpy(expiry.data, expiry_str, 8);

    unsigned char serialized_certificate[XTT_SERVER_CERTIFICATE_ED25519_LENGTH];
    rc = generate_server_certificate_ed25519(serialized_certificate,
                                             &server_id,
                                             &public_key,
                                             &expiry,
                                             &root_id,
                                             &root_priv_key);
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error creating certificate\n");
        return 1;
    }

    // 3) Write info to files
    int write_ret;
    write_ret = write_buffer_to_file(server_privatekey_file, server_private_key.data, sizeof(xtt_ed25519_priv_key));
    if (sizeof(xtt_ed25519_priv_key) != write_ret) {
        fprintf(stderr, "Error writing server's private key to file\n");
        return 1;
    }
    write_ret = write_buffer_to_file(server_certificate_file, serialized_certificate, XTT_SERVER_CERTIFICATE_ED25519_LENGTH);
    if (XTT_SERVER_CERTIFICATE_ED25519_LENGTH != write_ret) {
        fprintf(stderr, "Error writing server certificate to file\n");
        return 1;
    }
}
