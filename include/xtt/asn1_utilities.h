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

#ifndef XTT_ASN1_UTILITIES_H
#define XTT_ASN1_UTILITIES_H
#pragma once

#include <stddef.h>

#include <xtt/crypto_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XTT_X509_CERTIFICATE_LENGTH 276
size_t xtt_x509_certificate_length(void);

#define XTT_ASN1_PRIVATE_KEY_LENGTH 48
size_t xtt_asn1_private_key_length(void);

int xtt_x509_from_ed25519_keypair(const xtt_ed25519_pub_key *pub_key_in,
                                  const xtt_ed25519_priv_key *priv_key_in,
                                  const xtt_identity_type *common_name,
                                  unsigned char *certificate_out,
                                  size_t certificate_out_length);

int xtt_asn1_from_ed25519_private_key(const xtt_ed25519_priv_key *priv_key_in,
                                      unsigned char *asn1_out,
                                      size_t asn1_out_length);

#ifdef __cplusplus
}
#endif

#endif
