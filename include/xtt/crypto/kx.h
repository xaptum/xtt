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

#ifndef XTT_CRYPTO_KX_H
#define XTT_CRYPTO_KX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

/**
 * Fixed sized buffers for specific key exchange algorithms.
 *
 * They are used to ensure that the :xtt_crypto_kx_XXX: generic
 * buffers are large enough for any key exchange type.
 */
typedef struct {unsigned char data[32];} xtt_crypto_x25519_public;
typedef struct {unsigned char data[32];} xtt_crypto_x25519_secret;
typedef struct {unsigned char data[32];} xtt_crypto_x25519_shared;

/**
 * Generic buffer holding a public key for key exchange. The buffer
 * can be sized to hold the public key of any key exchange algorithm
 * supported by XTT.
 *
 * Call :xtt_crypto_kx_public_set() to initialize the public key from
 * a char buffer.
 *
 * @buf the first byte of the key
 * @len the size in bytes of the key
 */
struct xtt_crypto_kx_public {
    union {
        unsigned char buf;
        xtt_crypto_x25519_public x25519;
    };
    uint16_t len;
};

/**
 * Generic buffer holding a secret key for key exchange. The buffer
 * can be sized to hold the secret key of any key exchange algorithm
 * supported by XTT.
 *
 * @buf the first byte of the key
 * @len the size in bytes of the key
 */
struct xtt_crypto_kx_secret {
    union {
        unsigned char buf;
        xtt_crypto_x25519_secret x25519;
    };
    uint16_t len;
};

/**
 * Generic buffer holding a shared secret from key exchange. The
 * buffer can be sized to hold the shared secret from any key exchange
 * algorithm supported by XTT.
 *
 * @buf the first byte of the shared secret
 * @len the size in bytes of the shared secret
 */
struct xtt_crypto_kx_shared {
    union {
        unsigned char buf;
        xtt_crypto_x25519_shared x25519;
    };
    uint16_t len;
};

/**
 * Set the value of a :xtt_crypto_kx_public: key.
 *
 * @public_key the public key to set
 * @buf the buffer holding the value
 * @buflen the size in bytes of value
 */
inline static
void
xtt_crypto_kx_public_set(struct xtt_crypto_kx_public* public_key,
                         unsigned char* buf,
                         uint16_t buflen)
{
    public_key->len = buflen;
    memcpy(&public_key->buf, buf, public_key->len);
}

/**
 * A generic interface for a key exchange algorithm.
 */
struct xtt_crypto_kx_ops {
    /**
     * The size in bytes of the public key.
     */
    uint16_t public_len;

    /**
     * The size in bytes of the exchanged shared secret.
     */
    uint16_t shared_len;

    /**
     * Generates a new key pair.
     *
     * @public_key the destination for the generated public key
     * @secret_key the destination for the generated secret key
     */
    int (*keypair)(struct xtt_crypto_kx_public* public_key,
                   struct xtt_crypto_kx_secret* secret_key);

    /**
     * Computes the shared secret.
     *
     * @shared the destination for the shared secret
     * @other_public the other party's public key
     * @my_secret my secret key
     */
    int (*exchange)(struct xtt_crypto_kx_shared* shared,
                    const struct xtt_crypto_kx_public* other_public,
                    const struct xtt_crypto_kx_secret* my_secret);
};

#ifdef __cplusplus
}
#endif

#endif
