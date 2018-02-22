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

#ifndef XTT_CONTEXT_H
#define XTT_CONTEXT_H
#pragma once

#include <xtt/crypto_types.h>
#include <xtt/error_codes.h>
#include <xtt/certificates.h>
#include <xtt/daa_wrapper.h>

#ifndef SESSION_CONTEXT_BUFFER_SIZE
#define SESSION_CONTEXT_BUFFER_SIZE 2048
#endif


#ifndef HANDSHAKE_CONTEXT_BUFFER_SIZE
#define HANDSHAKE_CONTEXT_BUFFER_SIZE 1024
#endif

#ifndef MAX_BASENAME_LENGTH
#define MAX_BASENAME_LENGTH 64
#endif

#ifndef HASH_BUFFER_SIZE
#define HASH_BUFFER_SIZE 1024
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct xtt_handshake_context {
    void (*copy_dh_pubkey)(unsigned char* out,
                           uint16_t* out_length,
                           const struct xtt_handshake_context* self);

    int (*do_diffie_hellman)(unsigned char* shared_secret,
                             const unsigned char* other_pk,
                             const struct xtt_handshake_context* self);

    int (*prf)(unsigned char* out,
               uint16_t out_len,
               const unsigned char* in,
               uint16_t in_len,
               const unsigned char* key,
               uint16_t key_len);

    int (*encrypt)(unsigned char* ciphertext,
                   uint16_t* ciphertext_len,
                   const unsigned char* message,
                   uint16_t msg_len,
                   const unsigned char* addl_data,
                   uint16_t addl_len,
                   struct xtt_handshake_context *self);

    int (*decrypt)(unsigned char* decrypted,
                   uint16_t* decrypted_len,
                   const unsigned char* ciphertext,
                   uint16_t ciphertext_len,
                   const unsigned char* addl_data,
                   uint16_t addl_len,
                   struct xtt_handshake_context *self);

    int (*hash)(unsigned char* out,
                uint16_t* out_length,
                const unsigned char* in,
                uint16_t in_len);

    xtt_suite_spec suite_spec;
    xtt_version version;

    uint16_t longterm_key_length;
    uint16_t longterm_key_signature_length;
    uint16_t shared_secret_length;
    uint16_t hash_length;
    uint16_t mac_length;
    uint16_t key_length;
    uint16_t iv_length;

    xtt_sequence_number tx_sequence_num;
    xtt_sequence_number rx_sequence_num;

    union {
        xtt_x25519_pub_key x25519;
    } dh_pub_key;
    union {
        xtt_x25519_priv_key x25519;
    } dh_priv_key;

    union {
        xtt_chacha_key chacha;
        xtt_aes256_key aes256;
    } rx_key;
    union {
        xtt_chacha_nonce chacha;
        xtt_aes256_nonce aes256;
    } rx_iv;
    union {
        xtt_chacha_key chacha;
        xtt_aes256_key aes256;
    } tx_key;
    union {
        xtt_chacha_nonce chacha;
        xtt_aes256_nonce aes256;
    } tx_iv;

    union {
        xtt_sha512 sha512;
        xtt_blake2b blake2b;
    } hash_out_buffer_raw;
    unsigned char *hash_out_buffer;

    union {
        xtt_sha512 sha512;
        xtt_blake2b blake2b;
    } inner_hash_raw;
    unsigned char *inner_hash;

    union {
        xtt_sha512 sha512;
        xtt_blake2b blake2b;
    } prf_key_raw;
    unsigned char *prf_key;

    union {
        xtt_x25519_shared_secret x25519;
    } shared_secret_raw;
    unsigned char *shared_secret_buffer;

    union {
        xtt_sha512 sha512;
        xtt_blake2b blake2b;
    } handshake_secret_raw;
    unsigned char *handshake_secret;

    xtt_server_cookie server_cookie;
    unsigned char hash_buffer[HASH_BUFFER_SIZE];
    unsigned char client_init_buffer[80];
    unsigned char server_initandattest_buffer[200];
    unsigned char server_signature_buffer[sizeof(xtt_ed25519_signature)];
    // TODO: properly size this
    unsigned char clientattest_buffer[1024];
    unsigned char buffer[HANDSHAKE_CONTEXT_BUFFER_SIZE];
    /* TODO: Add a state? (so we're sure where in a handshake a given ctx is) */
};

struct xtt_server_handshake_context {
    struct xtt_handshake_context base;

    void (*read_longterm_key)(struct xtt_server_handshake_context *self,
                              uint16_t* key_length,
                              unsigned char* key_in);

    int (*verify_client_longterm_signature)(const unsigned char *signature,
                                            const unsigned char *msg,
                                            uint16_t msg_len,
                                            const unsigned char *client_longterm_key);

    union {
        xtt_ed25519_pub_key ed25519;
    } clients_longterm_key;
};

struct xtt_client_handshake_context {
    struct xtt_handshake_context base;

    int (*verify_server_signature)(const unsigned char *signature,
                                   const unsigned char *msg,
                                   uint16_t msg_len,
                                   const unsigned char *server_public_key);

    void (*copy_longterm_key)(unsigned char* out,
                              uint16_t* out_length,
                              const struct xtt_client_handshake_context *self);

    int (*compare_longterm_keys)(unsigned char *other_key,
                                 const struct xtt_client_handshake_context *self);
    int (*longterm_sign)(unsigned char *signature_out,
                         const unsigned char *msg,
                         uint16_t msg_len,
                         const struct xtt_client_handshake_context *self);

    union {
        xtt_ed25519_pub_key ed25519;
    } longterm_key;
    union {
        xtt_ed25519_priv_key ed25519;
    } longterm_private_key;
};

struct xtt_server_cookie_context {
    void *_;    // we're not currently using this context
};

struct xtt_server_certificate_context {
    int (*sign)(unsigned char *signature_out,
                const unsigned char *msg,
                uint16_t msg_len,
                const struct xtt_server_certificate_context *self);
    uint16_t signature_length;
    unsigned char serialized_certificate_raw[XTT_SERVER_CERTIFICATE_ED25519_LENGTH];
    struct xtt_server_certificate_raw_type *serialized_certificate;

    union {
        xtt_ed25519_priv_key ed25519;
    } private_key;
};

struct xtt_server_root_certificate_context {
    int (*verify_signature)(const unsigned char *signature,
                            const struct xtt_server_certificate_raw_type *certificate,
                            const struct xtt_server_root_certificate_context *self);
    xtt_server_signature_type type;
    xtt_certificate_root_id id;

    union {
        xtt_ed25519_pub_key ed25519;
    } public_key;
};

struct xtt_daa_group_public_key_context {
    int (*verify_signature)(unsigned char *signature,
                            unsigned char *msg,
                            uint16_t msg_len,
                            struct xtt_daa_group_public_key_context *self);
    unsigned char basename[MAX_BASENAME_LENGTH];
    uint16_t basename_length;

    union {
        xtt_daa_group_pub_key_lrsw lrsw;
    } gpk;
};

struct xtt_daa_context {
    int (*sign)(unsigned char *signature_out,
                const unsigned char *msg,
                uint16_t msg_len,
                struct xtt_daa_context *self);
    xtt_daa_group_id gid;
    union {
        xtt_daa_priv_key_lrsw lrsw;
    } priv_key;   // If NOT using a TPM
    union {
        xtt_daa_credential_lrsw lrsw;
    } cred;
    unsigned char basename[MAX_BASENAME_LENGTH];
    uint16_t basename_length;
    struct xtt_daa_tpm_context *tpm_context; // If using a TPM
};

xtt_error_code
xtt_initialize_server_handshake_context(struct xtt_server_handshake_context* ctx_out,
                                        xtt_version version,
                                        xtt_suite_spec suite_spec);

xtt_error_code
xtt_initialize_client_handshake_context(struct xtt_client_handshake_context* ctx_out,
                                        xtt_version version,
                                        xtt_suite_spec suite_spec);

xtt_error_code
xtt_initialize_server_cookie_context(struct xtt_server_cookie_context* ctx);

xtt_error_code
xtt_initialize_server_certificate_context_ed25519(struct xtt_server_certificate_context *ctx_out,
                                                  const unsigned char *serialized_certificate,
                                                  xtt_ed25519_priv_key *private_key);

xtt_error_code
xtt_initialize_server_root_certificate_context_ed25519(struct xtt_server_root_certificate_context *cert_out,
                                                       xtt_certificate_root_id *id,
                                                       xtt_ed25519_pub_key *public_key);

xtt_error_code
xtt_initialize_daa_group_public_key_context_lrsw(struct xtt_daa_group_public_key_context *ctx_out,
                                                 const unsigned char *basename,
                                                 uint16_t basename_length,
                                                 xtt_daa_group_pub_key_lrsw *gpk);

xtt_error_code
xtt_initialize_daa_context_lrswTPM(struct xtt_daa_context *ctx_out,
                                   xtt_daa_group_id *gid,
                                   xtt_daa_credential_lrsw *cred,
                                   const unsigned char *basename,
                                   uint16_t basename_length,
                                   struct xtt_daa_tpm_context *tpm_context);

xtt_error_code
xtt_initialize_daa_context_lrsw(struct xtt_daa_context *ctx_out,
                                xtt_daa_group_id *gid,
                                xtt_daa_priv_key_lrsw *priv_key,
                                xtt_daa_credential_lrsw *cred,
                                const unsigned char *basename,
                                uint16_t basename_length);

xtt_error_code
xtt_get_clients_longterm_key_ed25519(xtt_ed25519_pub_key *longterm_key_out,
                                     const struct xtt_server_handshake_context *handshake_context);

xtt_error_code
xtt_get_my_longterm_key_ed25519(xtt_ed25519_pub_key *longterm_key_out,
                                const struct xtt_client_handshake_context *handshake_context);

xtt_error_code
xtt_get_my_longterm_private_key_ed25519(xtt_ed25519_priv_key *longterm_key_priv_out,
                                        const struct xtt_client_handshake_context *handshake_context);

#ifdef __cplusplus
}
#endif

#endif

