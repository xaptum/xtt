/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
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

#ifndef XTT_UTIL_ASN1_H
#define XTT_UTIL_ASN1_H
#pragma once

#include <stddef.h>

#ifdef USE_TPM
#include <xaptum-tpm/keys.h>
#endif

#include <xtt/crypto_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XTT_X509_CERTIFICATE_LENGTH 352
size_t xtt_x509_certificate_length(void);

#define XTT_ASN1_PRIVATE_KEY_LENGTH 121
size_t xtt_asn1_private_key_length(void);


/*
 * Creates a x509 certificate from pub_key_in, priv_key_in, and common_name
 * and writes the certificate into certificate_out
 *
 * Returns:
 * 0 on success
 * CERT_CREATION_ERROR on failure
*/
int xtt_x509_from_ecdsap256_keypair(const xtt_ecdsap256_pub_key *pub_key_in,
                                  const xtt_ecdsap256_priv_key *priv_key_in,
                                  const xtt_identity_type *common_name,
                                  unsigned char *certificate_out,
                                  size_t certificate_out_length);

#ifdef USE_TPM
/*
 * Same as above, but uses a TPM signing key.
 */
int xtt_x509_from_ecdsap256_TPM(const xtt_ecdsap256_pub_key *pub_key_in,
                                const struct xtpm_key *priv_key_in,
                                TSS2_TCTI_CONTEXT *tcti_context,
                                const xtt_identity_type *common_name,
                                unsigned char *certificate_out,
                                size_t certificate_out_length);
#endif

/*
 * Writes the ECDSA keypair from the keys given
 *
 * Returns:
 *      0   on success
 *      SAVE_TO_FILE_ERROR   an error occurred writing to a file
 *      ASN1_CREATION_ERROR  an error occurred creating the ASN.1 keypair
 *
*/
int xtt_write_ecdsap256_keypair(xtt_ecdsap256_pub_key *pub_key, xtt_ecdsap256_priv_key *priv_key, const char *keypair_file);

/*
 * Reads a ECDSA keypair and saves the keys to their own types
 *
 * Returns:
 *      0   on success
 *      READ_TO_FILE_ERROR   an error occurred reading from a file
 *      ASN1_PARSE_ERROR     an error occurred parsing the given keypair
*/
int xtt_read_ecdsap256_keypair(const char* keypair_file, xtt_ecdsap256_pub_key *pub_key, xtt_ecdsap256_priv_key *priv_key);

#ifdef __cplusplus
}
#endif

#endif
