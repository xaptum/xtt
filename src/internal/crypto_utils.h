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

#ifndef XTT_CRYPTO_UTILS_INTERNAL_H
#define XTT_CRYPTO_UTILS_INTERNAL_H
#pragma once

#include <xtt/crypto_types.h>
#include <xtt/crypto.h>
#include <xtt/context.h>

#ifdef __cplusplus
extern "C" {
#endif

void prepare_aead_nonce(struct xtt_crypto_aead_nonce* nonce,
                        xtt_sequence_number* seqnum,
                        const struct xtt_crypto_aead_nonce* iv);

void copy_longterm_key_ecdsap256(unsigned char* out,
                               uint16_t* out_length,
                               const struct xtt_client_handshake_context* self);


int compare_longterm_keys_ecdsap256(unsigned char *other_key,
                                  const struct xtt_client_handshake_context *self);

void read_longterm_key_ecdsap256(struct xtt_server_handshake_context *self,
                               uint16_t* key_length,
                               unsigned char* key_in);

int verify_server_signature_ecdsap256(const unsigned char *signature,
                                    const unsigned char *msg,
                                    uint16_t msg_len,
                                    const unsigned char *server_public_key);

int sign_server_ecdsap256(unsigned char *signature_out,
                        const unsigned char *msg,
                        uint16_t msg_len,
                        const struct xtt_server_certificate_context *self);

int longterm_sign_ecdsap256(unsigned char *signature_out,
                          const unsigned char *msg,
                          uint16_t msg_len,
                          const struct xtt_client_handshake_context *self);

#ifdef USE_TPM
int longterm_sign_ecdsap256TPM(unsigned char *signature_out,
                               const unsigned char *msg,
                               uint16_t msg_len,
                               const struct xtt_client_handshake_context *self);
#endif

int verify_root_ecdsap256(const unsigned char *signature,
                        const struct xtt_server_certificate_raw_type *certificate,
                        const struct xtt_server_root_certificate_context *self);

#ifdef USE_TPM
int sign_lrswTPM(unsigned char *signature_out,
                 const unsigned char *msg,
                 uint16_t msg_len,
                 struct xtt_client_group_context *self);
#endif

int sign_lrsw(unsigned char *signature_out,
              const unsigned char *msg,
              uint16_t msg_len,
              struct xtt_client_group_context *self);

int verify_lrsw(unsigned char *signature,
                unsigned char *msg,
                uint16_t msg_len,
                struct xtt_group_public_key_context *self);

int copy_pseudonym_lrsw(unsigned char *out,
                        uint16_t *out_length,
                        unsigned char *serialized_signature_in);

int copy_in_pseudonym_server_lrsw(struct xtt_server_handshake_context *self,
                                  unsigned char *signature_in);

int copy_in_pseudonym_client_lrsw(struct xtt_client_handshake_context *self,
                                  unsigned char *signature_in);

#ifdef __cplusplus
}
#endif

#endif
