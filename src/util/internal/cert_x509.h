/******************************************************************************
 *
 * Copyright 2017-2020 Xaptum, Inc.
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

#ifndef XTT_INTERNAL_CERT_X509_H
#define XTT_INTERNAL_CERT_X509_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <xtt/crypto_types.h>

#include <stddef.h>

#define P256_BIGNUM_SIZE 32

void
build_x509_preamble(const xtt_identity_string *common_name,
                    const xtt_ecdsap256_pub_key *pub_key,
                    unsigned char *certificate_out,
                    unsigned char **to_be_signed_location_out,
                    size_t *to_be_signed_length_out);

void
append_x509_signature(const unsigned char *signature_r,
                      const unsigned char *signature_s,
                      unsigned char *certificate_out);

size_t
certificate_length(const unsigned char *certificate);

#ifdef __cplusplus
}
#endif

#endif
