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

#ifndef XTT_CRYPTO_TYPES_H
#define XTT_CRYPTO_TYPES_H
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum xtt_version {
    XTT_VERSION_ONE = 0x01
} xtt_version;

typedef enum xtt_suite_spec {
    XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512    = 0x0001,
    XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B   = 0x0002,
    XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512           = 0x0003,
    XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B          = 0x0004,
} xtt_suite_spec;

typedef enum xtt_msg_type {
    XTT_CLIENTINIT_MSG                                      = 0x01,
    XTT_SERVERINITANDATTEST_MSG                             = 0x02,

    XTT_ID_CLIENTATTEST_MSG                                 = 0x11,
    XTT_ID_SERVERFINISHED_MSG                               = 0x13,

    XTT_SESSION_CLIENTATTEST_NOPAYLOAD_MSG                  = 0x21,
    XTT_SESSION_CLIENTATTEST_PAYLOAD_MSG                    = 0x22,
    XTT_SESSION_SERVERFINISHED_MSG                          = 0x23,

    XTT_RECORD_REGULAR_MSG                                  = 0x31,

    XTT_ERROR_MSG                                           = 0x41
} xtt_msg_type;

typedef enum xtt_encapsulated_payload_type {
    XTT_ENCAPSULATED_QUEUE_PROTO                            = 0x01,
    XTT_ENCAPSULATED_IPV6                                   = 0x02
} xtt_encapsulated_payload_type;

typedef uint8_t xtt_msg_type_raw;
typedef uint8_t xtt_version_raw;
typedef uint16_t xtt_suite_spec_raw;
typedef uint8_t xtt_encapsulated_payload_type_raw;
typedef uint32_t xtt_sequence_number;
typedef uint16_t xtt_length;
typedef struct {unsigned char data[32];} xtt_signing_nonce;
typedef struct {unsigned char data[8];} xtt_session_id_seed;
typedef struct {unsigned char data[16];} xtt_session_id;
typedef struct {unsigned char data[16];} xtt_identity_type;
typedef struct {char data[40];} xtt_identity_string;
extern const xtt_identity_type xtt_null_identity;
typedef struct {unsigned char data[130];} xtt_server_cookie;

/* Client group signatures */
typedef struct {unsigned char data[32];} xtt_group_id;

typedef struct {unsigned char data[260];} xtt_daa_credential_lrsw;
typedef struct {unsigned char data[32];} xtt_daa_priv_key_lrsw;
typedef struct {unsigned char data[258];} xtt_daa_group_pub_key_lrsw;
typedef struct {unsigned char data[421];} xtt_daa_signature_lrsw;
typedef struct {unsigned char data[65];} xtt_daa_pseudonym_lrsw;

/* Diffie-Hellman */
typedef struct {unsigned char data[32];} xtt_x25519_pub_key;
typedef struct {unsigned char data[32];} xtt_x25519_priv_key;
typedef struct {unsigned char data[32];} xtt_x25519_shared_secret;

/* LongtermSignature types */
typedef enum xtt_server_signature_type {
    XTT_SERVER_SIGNATURE_TYPE_ECDSAP256 = 1,
} xtt_server_signature_type;

typedef struct {unsigned char data[65];} xtt_ecdsap256_pub_key;
typedef struct {unsigned char data[32];} xtt_ecdsap256_priv_key;
typedef struct {unsigned char data[64];} xtt_ecdsap256_signature;

typedef struct {unsigned char data[24];} xtt_certificate_reserved;

typedef struct {unsigned char data[16];} xtt_certificate_root_id;
extern const xtt_certificate_root_id xtt_null_server_root_id;

/* AEAD key types */
typedef struct {unsigned char data[32];} xtt_chacha_key;
typedef struct {unsigned char data[12];} xtt_chacha_nonce;
typedef struct {unsigned char data[16];} xtt_chacha_mac;

typedef struct {unsigned char data[32];} xtt_aes256_key;
typedef struct {unsigned char data[12];} xtt_aes256_nonce;
typedef struct {unsigned char data[16];} xtt_aes256_mac;

int
xtt_identity_to_string(const xtt_identity_type *identity_in,
                       xtt_identity_string *string_out);

#ifdef __cplusplus
}
#endif

#endif
