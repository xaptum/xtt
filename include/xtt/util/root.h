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

#ifndef XTT_UTIL_GEN_ROOT_H
#define XTT_UTIL_GEN_ROOT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <xtt/crypto_types.h>

typedef struct {unsigned char data[sizeof(xtt_certificate_root_id) + sizeof(xtt_ecdsap256_pub_key)];} xtt_root_certificate;

/*
 * Serialize the provided root public information into the provided certificate. [ ID | Public Key]
 */
void xtt_serialize_root_certificate(xtt_ecdsap256_pub_key *pub_key, xtt_certificate_root_id *id, xtt_root_certificate *info_out);

/*
 * Deserialize the provided root certificate and write the public key and ID into their own buffers.
 */
void xtt_deserialize_root_certificate(xtt_ecdsap256_pub_key *pub_key, xtt_certificate_root_id *root_id, xtt_root_certificate *root_cert_in);

/*
 * Generates a root certificate.
 *
 * Returns:
 *      0                       on success
 *      SAVE_TO_FILE_ERROR      an error occurred writing to a file
 *      READ_FROM_FILE_ERROR    an error occurred reading from a file
 *      KEY_CREATION_ERROR      an error occurred creating a keypair
*/
int xtt_generate_root(const char *privkey_filename, const char *pubkey_filename, const char *id_filename, const char *cert_filename);

#ifdef __cplusplus
}
#endif

#endif
