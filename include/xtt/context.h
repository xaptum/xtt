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

#include <xtt/crypto.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>
#include <xtt/certificates.h>
#include <xtt/daa_wrapper.h>

#ifdef USE_TPM
#include <xaptum-tpm/keys.h>
#include <tss2/tss2_sys.h>
#endif

#define SESSION_CONTEXT_BUFFER_SIZE 2048


#define HANDSHAKE_CONTEXT_BUFFER_SIZE 1024

#ifndef MAX_BASENAME_LENGTH
#define MAX_BASENAME_LENGTH 64
#endif

#ifndef MAX_TPM_PASSWORD_LENGTH
#define MAX_TPM_PASSWORD_LENGTH 64
#endif

#define HASH_BUFFER_SIZE 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    XTT_CLIENT_HANDSHAKE_STATE_START,
    XTT_CLIENT_HANDSHAKE_STATE_SENDING_CLIENTINIT,
    XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTESTHEADER,
    XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTEST,
    XTT_CLIENT_HANDSHAKE_STATE_PREPARSING_SERVERATTEST,
    XTT_CLIENT_HANDSHAKE_STATE_BUILDING_IDCLIENTATTEST,
    XTT_CLIENT_HANDSHAKE_STATE_SENDING_IDCLIENTATTEST,
    XTT_CLIENT_HANDSHAKE_STATE_READING_IDSERVERFINISHEDHEADER,
    XTT_CLIENT_HANDSHAKE_STATE_READING_IDSERVERFINISHED,
    XTT_CLIENT_HANDSHAKE_STATE_PARSING_IDSERVERFINISHED,
    XTT_CLIENT_HANDSHAKE_STATE_FINISHED,
    XTT_CLIENT_HANDSHAKE_STATE_ERROR,
} xtt_client_handshake_state;

typedef enum {
    XTT_SERVER_HANDSHAKE_STATE_START,
    XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTINITHEADER,
    XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTINIT,
    XTT_SERVER_HANDSHAKE_STATE_PARSING_CLIENTINIT_AND_BUILDING_SERVERATTEST,
    XTT_SERVER_HANDSHAKE_STATE_SENDING_SERVERATTEST,
    XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTATTESTHEADER,
    XTT_SERVER_HANDSHAKE_STATE_READING_IDCLIENTATTEST,
    XTT_SERVER_HANDSHAKE_STATE_PREPARSING_IDCLIENTATTEST,
    XTT_SERVER_HANDSHAKE_STATE_VERIFYING_GROUPSIGNATURE,
    XTT_SERVER_HANDSHAKE_STATE_BUILDING_IDSERVERFINISHED,
    XTT_SERVER_HANDSHAKE_STATE_SENDING_IDSERVERFINISHED,
    XTT_SERVER_HANDSHAKE_STATE_FINISHED,
    XTT_SERVER_HANDSHAKE_STATE_ERROR,
} xtt_server_handshake_state;

struct xtt_handshake_context {

    xtt_suite_spec suite_spec;
    const struct xtt_suite_ops* suite_ops;
    xtt_version version;

    unsigned char *in_buffer_start;
    unsigned char *in_message_start;
    unsigned char *in_end;
    unsigned char *out_buffer_start;
    unsigned char *out_message_start;
    unsigned char *out_end;

    uint16_t longterm_key_length;
    uint16_t longterm_key_signature_length;

    xtt_sequence_number tx_sequence_num;
    xtt_sequence_number rx_sequence_num;

    struct xtt_crypto_kx_public kx_pubkey;
    struct xtt_crypto_kx_secret kx_seckey;
    struct xtt_crypto_kx_shared kx_shared;

    struct xtt_crypto_aead_key rx_key;
    struct xtt_crypto_aead_key tx_key;
    struct xtt_crypto_aead_nonce rx_iv;
    struct xtt_crypto_aead_nonce tx_iv;

    struct xtt_crypto_hmac hash_out;
    struct xtt_crypto_hmac inner_hash;
    struct xtt_crypto_hmac prf_key;
    struct xtt_crypto_hmac handshake_secret;

    xtt_server_cookie server_cookie;
    unsigned char hash_buffer[HASH_BUFFER_SIZE];
    unsigned char client_init_buffer[80];
    unsigned char server_initandattest_buffer[233];
    unsigned char server_signature_buffer[sizeof(xtt_ecdsap256_signature)];
    // TODO: properly size this
    unsigned char clientattest_buffer[1024];
    unsigned char buffer[HANDSHAKE_CONTEXT_BUFFER_SIZE];
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

    int (*copy_in_clients_pseudonym)(struct xtt_server_handshake_context *self,
                                     unsigned char *signature_in);

    xtt_server_handshake_state state;

    xtt_identity_type clients_identity;

    union {
        xtt_ecdsap256_pub_key ecdsap256;
    } clients_longterm_key;

    union {
        xtt_daa_pseudonym_lrsw lrsw;
    } clients_pseudonym;
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

    int (*copy_in_my_pseudonym)(struct xtt_client_handshake_context *self,
                                unsigned char *signature_in);

    xtt_client_handshake_state state;

    xtt_identity_type identity;

    union {
        xtt_daa_pseudonym_lrsw lrsw;
    } pseudonym;

    union {
        xtt_ecdsap256_pub_key ecdsap256;
    } longterm_key;
    union {
        xtt_ecdsap256_priv_key ecdsap256;
    } longterm_private_key;

#ifdef USE_TPM
    TSS2_TCTI_CONTEXT *tcti_context;

    TPMI_RH_HIERARCHY hierarchy;
    char hierarchy_password[MAX_TPM_PASSWORD_LENGTH];
    size_t hierarchy_password_length;

    TPM2_HANDLE parent_handle;
    struct xtpm_key longterm_private_key_tpm;
#endif
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
    unsigned char serialized_certificate_raw[XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH];
    struct xtt_server_certificate_raw_type *serialized_certificate;

    union {
        xtt_ecdsap256_priv_key ecdsap256;
    } private_key;
};

struct xtt_server_root_certificate_context {
    int (*verify_signature)(const unsigned char *signature,
                            const struct xtt_server_certificate_raw_type *certificate,
                            const struct xtt_server_root_certificate_context *self);
    xtt_server_signature_type type;
    xtt_certificate_root_id id;

    union {
        xtt_ecdsap256_pub_key ecdsap256;
    } public_key;
};

struct xtt_group_public_key_context {
    int (*verify_signature)(unsigned char *signature,
                            unsigned char *msg,
                            uint16_t msg_len,
                            struct xtt_group_public_key_context *self);
    unsigned char basename[MAX_BASENAME_LENGTH];
    uint16_t basename_length;

    union {
        xtt_daa_group_pub_key_lrsw lrsw;
    } gpk;
};

struct xtt_client_group_context {
    int (*sign)(unsigned char *signature_out,
                const unsigned char *msg,
                uint16_t msg_len,
                struct xtt_client_group_context *self);
    xtt_group_id gid;
    union {
        xtt_daa_credential_lrsw lrsw;
    } cred;
    unsigned char basename[MAX_BASENAME_LENGTH];
    uint16_t basename_length;

    // If NOT using a TPM:
    union {
        xtt_daa_priv_key_lrsw lrsw;
    } priv_key;

#ifdef USE_TPM
    // If using a TPM:
    TPM_HANDLE key_handle;
    char key_password[MAX_TPM_PASSWORD_LENGTH];
    uint16_t key_password_length;
    TSS2_TCTI_CONTEXT *tcti_context;
#endif
};

xtt_return_code_type
xtt_initialize_client_handshake_context(struct xtt_client_handshake_context* ctx_out,
                                        unsigned char *in_buffer,
                                        uint16_t in_buffer_size,
                                        unsigned char *out_buffer,
                                        uint16_t out_buffer_size,
                                        xtt_version version,
                                        xtt_suite_spec suite_spec);

#ifdef USE_TPM
xtt_return_code_type
xtt_initialize_client_handshake_context_TPM(struct xtt_client_handshake_context* ctx_out,
                                            unsigned char *in_buffer,
                                            uint16_t in_buffer_size,
                                            unsigned char *out_buffer,
                                            uint16_t out_buffer_size,
                                            xtt_version version,
                                            xtt_suite_spec suite_spec,
                                            TPMI_RH_HIERARCHY hierarchy,
                                            const char *hierarchy_password,
                                            size_t hierarchy_password_length,
                                            TPM2_HANDLE parent_handle,
                                            TSS2_TCTI_CONTEXT *tcti_context);
#endif

xtt_return_code_type
xtt_initialize_server_handshake_context(struct xtt_server_handshake_context* ctx_out,
                                        unsigned char *in_buffer,
                                        uint16_t in_buffer_size,
                                        unsigned char *out_buffer,
                                        uint16_t out_buffer_size);

xtt_return_code_type
xtt_initialize_server_cookie_context(struct xtt_server_cookie_context* ctx);

xtt_return_code_type
xtt_initialize_server_certificate_context_ecdsap256(struct xtt_server_certificate_context *ctx_out,
                                                  const unsigned char *serialized_certificate,
                                                  const xtt_ecdsap256_priv_key *private_key);

xtt_return_code_type
xtt_initialize_server_root_certificate_context_ecdsap256(struct xtt_server_root_certificate_context *cert_out,
                                                       xtt_certificate_root_id *id,
                                                       xtt_ecdsap256_pub_key *public_key);

xtt_return_code_type
xtt_initialize_group_public_key_context_lrsw(struct xtt_group_public_key_context *ctx_out,
                                                 const unsigned char *basename,
                                                 uint16_t basename_length,
                                                 const xtt_daa_group_pub_key_lrsw *gpk);

#ifdef USE_TPM
xtt_return_code_type
xtt_initialize_client_group_context_lrswTPM(struct xtt_client_group_context *ctx_out,
                                            xtt_group_id *gid,
                                            xtt_daa_credential_lrsw *cred,
                                            const unsigned char *basename,
                                            uint16_t basename_length,
                                            TPM_HANDLE key_handle,
                                            const char *key_password,
                                            uint16_t key_password_length,
                                            TSS2_TCTI_CONTEXT *tcti_context);
#endif

xtt_return_code_type
xtt_initialize_client_group_context_lrsw(struct xtt_client_group_context *ctx_out,
                                xtt_group_id *gid,
                                xtt_daa_priv_key_lrsw *priv_key,
                                xtt_daa_credential_lrsw *cred,
                                const unsigned char *basename,
                                uint16_t basename_length);

xtt_return_code_type
xtt_get_version(xtt_version *version_out,
                const struct xtt_server_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_suite_spec(xtt_suite_spec *suite_spec_out,
                   const struct xtt_server_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_clients_longterm_key_ecdsap256(xtt_ecdsap256_pub_key *longterm_key_out,
                                     const struct xtt_server_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_clients_identity(xtt_identity_type *client_id_out,
                          const struct xtt_server_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_clients_pseudonym_lrsw(xtt_daa_pseudonym_lrsw *pseudonym_out,
                               const struct xtt_server_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_my_longterm_key_ecdsap256(xtt_ecdsap256_pub_key *longterm_key_out,
                                const struct xtt_client_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_my_longterm_private_key_ecdsap256(xtt_ecdsap256_priv_key *longterm_key_priv_out,
                                        const struct xtt_client_handshake_context *handshake_context);

xtt_return_code_type
xtt_get_my_identity(xtt_identity_type *client_id_out,
                     const struct xtt_client_handshake_context *handshake_context);

xtt_return_code_type
xtt_setup_server_handshake_context(struct xtt_server_handshake_context* ctx_out,
                                   xtt_version version,
                                   xtt_suite_spec suite_spec);

xtt_return_code_type
xtt_get_my_pseudonym_lrsw(xtt_daa_pseudonym_lrsw *pseudonym_out,
                          const struct xtt_client_handshake_context *handshake_context);

#ifdef __cplusplus
}
#endif

#endif
