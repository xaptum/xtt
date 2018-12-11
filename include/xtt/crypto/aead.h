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

#pragma once

#ifndef XTT_CRYPTO_AEAD_H
#define XTT_CRYPTO_AEAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

/**
 * Fixed sized buffers for specific AEAD algorithms.
 *
 * They are used to ensure that the :xtt_crypto_aead_XXX: generic
 * buffers are large enough for any AEAD algorithm.
 */
typedef struct {unsigned char data[32];} xtt_crypto_aes256gcm_key;
typedef struct {unsigned char data[12];} xtt_crypto_aes256gcm_nonce;
typedef struct {unsigned char data[16];} xtt_crypto_aes256gcm_mac;

typedef struct {unsigned char data[32];} xtt_crypto_chacha20poly1305_key;
typedef struct {unsigned char data[12];} xtt_crypto_chacha20poly1305_nonce;
typedef struct {unsigned char data[16];} xtt_crypto_chacha20poly1305_mac;

/**
 * Generic buffer holding a secret key for AEAD. The buffer can be
 * sized to hold the secret key of any AEAD algorithm supported by
 * XTT.
 *
 * @buf the first byte of the key
 * @len the size in bytes of the key
 */
struct xtt_crypto_aead_key {
    union {
        unsigned char buf;
        xtt_crypto_aes256gcm_key aes256;
        xtt_crypto_chacha20poly1305_key chacha;
    };
    uint16_t len;
};

/**
 * Generic buffer holding a nonce for AEAD. The buffer can be sized to
 * hold the nonce of any AEAD algorithm supported by XTT.
 *
 * @buf the first byte of the nonce
 * @len the size in bytes of the nonce
 */
struct xtt_crypto_aead_nonce {
    union {
        unsigned char buf;
        xtt_crypto_aes256gcm_nonce aes256;
        xtt_crypto_chacha20poly1305_nonce chacha;
    };
    uint16_t len;
};

/**
 * A generic interface for an AEAD algorithm.
 */
struct xtt_crypto_aead_ops {
    /**
     * The size in bytes of the key.
     */
    uint16_t key_len;

    /**
     * The size in bytes of the mac. A ciphertext is :mac_len: bytes
     * longer than the corresponding plain text.
     */
    uint16_t mac_len;

    /**
     * The size in bytes of the nonce.
     */
    uint16_t nonce_len;

    /**
     * Encrypts the message and binds the associated data using the
     * provided key.
     *
     * @cipher the destination for ciphertext
     * @msg the message to encrypt
     * @msglen the size in bytes of the message
     * @ad the associated data to bind
     * @adlen the size in bytes of the associated data
     * @nonce the unique nonce for this message
     * @key the secret key
     */
    int (*encrypt)(unsigned char* cipher,
                   const unsigned char* msg,
                   uint16_t msglen,
                   const unsigned char* ad,
                   uint16_t adlen,
                   const struct xtt_crypto_aead_nonce* nonce,
                   const struct xtt_crypto_aead_key* key);

    /**
     * Decrypts the message and verifies the associated data using the
     * provided key.
     *
     * @cipher the destination for ciphertext
     * @msg the message to encrypt
     * @msglen the size in bytes of the message
     * @ad the associated data to bind
     * @adlen the size in bytes of the associated data
     * @nonce the unique nonce for this message
     * @key the secret key
     */
    int (*decrypt)(unsigned char* msg,
                   const unsigned char* cipher,
                   uint16_t cipherlen,
                   const unsigned char* ad,
                   uint16_t adlen,
                   const struct xtt_crypto_aead_nonce* nonce,
                   const struct xtt_crypto_aead_key* key);
};

/**
 * Initialize an :xtt_crypto_aead_key: buffer for use with a
 * particular algorithm.
 *
 * This function does *NOT* set the value of the key.
 *
 * @key the buffer to initialize
 * @ops the algorithm
 */
inline static
void
xtt_crypto_aead_key_init(struct xtt_crypto_aead_key* key,
                         struct xtt_crypto_aead_ops* ops) {
    memset(key, 0, sizeof(*key));
    key->len = ops->key_len;
}

/**
 * Initialize an :xtt_crypto_aead_nonce: buffer for use with a
 * particular algorithm.
 *
 * This function does *NOT* set the value of the nonce.
 *
 * @nonce the buffer to initialize
 * @ops the algorithm
 */
inline static
void
xtt_crypto_aead_nonce_init(struct xtt_crypto_aead_nonce* nonce,
                           struct xtt_crypto_aead_ops* ops) {
    memset(nonce, 0, sizeof(*nonce));
    nonce->len = ops->nonce_len;
}

#ifdef __cplusplus
}
#endif

#endif
