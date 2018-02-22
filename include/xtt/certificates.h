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

#ifndef XTT_CERTIFICATES_H
#define XTT_CERTIFICATES_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <xtt/crypto_types.h>
#include <xtt/error_codes.h>

#define XTT_SERVER_CERTIFICATE_ED25519_LENGTH 136

struct xtt_server_certificate_raw_type;

xtt_error_code
generate_server_certificate_ed25519(unsigned char *cert_out,
                                    xtt_client_id *servers_id,
                                    xtt_ed25519_pub_key *servers_pub_key,
                                    xtt_certificate_expiry *expiry,
                                    xtt_certificate_root_id *roots_id,
                                    xtt_ed25519_priv_key *roots_priv_key);

uint16_t
xtt_server_certificate_length_fromsignaturetype(xtt_server_signature_type type);

uint16_t
xtt_server_certificate_length(xtt_suite_spec suite_spec);

uint16_t
xtt_server_certificate_length_uptosignature_fromsignaturetype(xtt_server_signature_type type);

uint16_t
xtt_server_certificate_length_uptosignature(xtt_suite_spec suite_spec);

unsigned char*
xtt_server_certificate_access_id(const struct xtt_server_certificate_raw_type *certificate);

unsigned char*
xtt_server_certificate_access_expiry(const struct xtt_server_certificate_raw_type *certificate);

unsigned char*
xtt_server_certificate_access_rootid(const struct xtt_server_certificate_raw_type *certificate);

unsigned char*
xtt_server_certificate_access_pubkey(const struct xtt_server_certificate_raw_type *certificate);

unsigned char*
xtt_server_certificate_access_rootsignature_fromsignaturetype(const struct xtt_server_certificate_raw_type *certificate,
                                                              xtt_server_signature_type type);

unsigned char*
xtt_server_certificate_access_rootsignature(const struct xtt_server_certificate_raw_type *certificate,
                                            xtt_suite_spec suite_spec);

#ifdef __cplusplus
}
#endif

#endif

