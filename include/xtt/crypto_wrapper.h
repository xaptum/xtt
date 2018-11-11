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

int xtt_crypto_initialize_crypto();

int xtt_crypto_memcmp(const unsigned char *one, const unsigned char *two, uint16_t length);

void xtt_crypto_secure_clear(unsigned char* memory, uint16_t memory_length);

void xtt_crypto_get_random(unsigned char* buffer, uint16_t buffer_length);

int xtt_crypto_create_x25519_key_pair(xtt_x25519_pub_key *pub, xtt_x25519_priv_key *priv);

int xtt_crypto_do_x25519_diffie_hellman(unsigned char* shared_secret,
                                        const xtt_x25519_priv_key* my_sk,
                                        const xtt_x25519_pub_key* other_pk);

int xtt_crypto_hash_sha512(unsigned char* out,
                           uint16_t* out_length,
                           const unsigned char* in,
                           uint16_t in_len);

int xtt_crypto_hash_blake2b(unsigned char* out,
                            uint16_t* out_length,
                            const unsigned char* in,
                            uint16_t in_len);

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

int xtt_crypto_aead_chacha_encrypt(unsigned char* ciphertext,
                                   uint16_t* ciphertext_len,
                                   const unsigned char* message,
                                   uint16_t msg_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_chacha_nonce* nonce,
                                   const xtt_chacha_key* key);

int xtt_crypto_aead_chacha_decrypt(unsigned char* decrypted,
                                   uint16_t* decrypted_len,
                                   const unsigned char* ciphertext,
                                   uint16_t ciphertext_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_chacha_nonce* nonce,
                                   const xtt_chacha_key* key);

int xtt_crypto_aead_aes256_encrypt(unsigned char* ciphertext,
                                   uint16_t* ciphertext_len,
                                   const unsigned char* message,
                                   uint16_t msg_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_aes256_nonce* nonce,
                                   const xtt_aes256_key* key);

int xtt_crypto_aead_aes256_decrypt(unsigned char* decrypted,
                                   uint16_t* decrypted_len,
                                   const unsigned char* ciphertext,
                                   uint16_t ciphertext_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_aes256_nonce* nonce,
                                   const xtt_aes256_key* key);



#ifdef __cplusplus
}
#endif

#endif
