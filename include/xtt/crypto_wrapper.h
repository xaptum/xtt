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

#ifndef XTT_CRYPTO_WRAPPER_H
#define XTT_CRYPTO_WRAPPER_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <xtt/crypto_types.h>
#include <xtt/crypto.h>

int xtt_crypto_initialize_crypto();

int xtt_crypto_memcmp(const unsigned char *one, const unsigned char *two, uint16_t length);

void xtt_crypto_secure_clear(unsigned char* memory, uint16_t memory_length);

void xtt_crypto_get_random(unsigned char* buffer, uint16_t buffer_length);

int xtt_crypto_kx_x25519_keypair(struct xtt_crypto_kx_public* public,
                                 struct xtt_crypto_kx_secret* secret);

int xtt_crypto_kx_x25519_exchange(struct xtt_crypto_kx_shared* shared,
                                  const struct xtt_crypto_kx_public* other_public,
                                  const struct xtt_crypto_kx_secret* my_secret);

int xtt_crypto_hash_sha512(struct xtt_crypto_hmac* out,
                           const unsigned char* in,
                           uint16_t inlen);

int xtt_crypto_hash_blake2b(struct xtt_crypto_hmac* out,
                            const unsigned char* in,
                            uint16_t inlen);

int xtt_crypto_prf_sha512(unsigned char* out,
                          uint16_t out_len,
                          const unsigned char* in,
                          uint16_t in_len,
                          const unsigned char* key,
                          uint16_t key_len);

int xtt_crypto_prf_blake2b(unsigned char* out,
                           uint16_t out_len,
                           const unsigned char* in,
                           uint16_t in_len,
                           const unsigned char* key,
                           uint16_t key_len);

int xtt_crypto_create_ecdsap256_key_pair(xtt_ecdsap256_pub_key *pub_key,
                                       xtt_ecdsap256_priv_key *priv_key);

int xtt_crypto_sign_ecdsap256(unsigned char* signature_out,
                            const unsigned char* msg,
                            uint16_t msg_len,
                            const xtt_ecdsap256_priv_key* priv_key);

int xtt_crypto_verify_ecdsap256(const unsigned char* signature,
                              const unsigned char* msg,
                              uint16_t msg_len,
                              const xtt_ecdsap256_pub_key* pub_key);

int xtt_crypto_aead_chacha20poly1305_encrypt(unsigned char* cipher,
                                             const unsigned char* msg,
                                             uint16_t msglen,
                                             const unsigned char* ad,
                                             uint16_t adlen,
                                             const struct xtt_crypto_aead_nonce* nonce,
                                             const struct xtt_crypto_aead_key* key);

int xtt_crypto_aead_chacha20poly1305_decrypt(unsigned char* msg,
                                             const unsigned char* cipher,
                                             uint16_t cipherlen,
                                             const unsigned char* ad_data,
                                             uint16_t adlen,
                                             const struct xtt_crypto_aead_nonce* nonce,
                                             const struct xtt_crypto_aead_key* key);

int xtt_crypto_aead_aes256gcm_encrypt(unsigned char* cipher,
                                      const unsigned char* msg,
                                      uint16_t msglen,
                                      const unsigned char* ad,
                                      uint16_t adlen,
                                      const struct xtt_crypto_aead_nonce* nonce,
                                      const struct xtt_crypto_aead_key* key);

int xtt_crypto_aead_aes256gcm_decrypt(unsigned char* msg,
                                      const unsigned char* cipher,
                                      uint16_t cipherlen,
                                      const unsigned char* ad_data,
                                      uint16_t adlen,
                                      const struct xtt_crypto_aead_nonce* nonce,
                                      const struct xtt_crypto_aead_key* key);

#ifdef __cplusplus
}
#endif

#endif
