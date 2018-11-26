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

#ifndef XTT_CRYPTO_HMAC_H
#define XTT_CRYPTO_HMAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

/**
 * Fixed sized buffers for specific HMAC algorithms.
 *
 * They are used to ensure that the :xtt_crypto_hmac: generic buffer
 * is large enough for any HMAC output.
 */
typedef struct {unsigned char data[64];} xtt_crypto_sha512;
typedef struct {unsigned char data[64];} xtt_crypto_blake2b;

/**
 * Generic buffer for an HMAC output (a hash or PRF). The buffer can
 * be sized to hold the output of any HMAC algorithm supported by XTT.
 *
 * Call xtt_crypto_hmac_init() to initialize the buffer for use with a
 * particular algorithm.
 *
 * @buf the first byte of the buffer
 * @len the size of the buffer as initialized for a particular
 *      algorithm.
 */
struct xtt_crypto_hmac {
    union {
        unsigned char buf;
        xtt_crypto_sha512 sha512;
        xtt_crypto_blake2b blake2b;
    };
    uint16_t len;
};

/**
 * A generic interface for an HMAC algorithm.
 */
struct xtt_crypto_hmac_ops {
    /**
     * The size in bytes of the HMAC output.
     */
    const uint16_t outlen;

    /**
     * Computes the hash of the provided message.
     *
     * @out the destination for the computed hash
     * @msg the source buffer to hash
     * @msglen the size in bytes of the source buffer
     */
    int (*hash)(struct xtt_crypto_hmac* out,
                const unsigned char* msg,
                uint16_t msglen);

    /**
     * Evaluates a pseudorandom function on the provided input to
     * generate an output of the requested length.
     *
     * @out the destination buffer for the function output
     * @outlen the size in bytes of the output buffer
     * @in the source buffer on which to evaluation the function
     * @inlen the size in bytes of the source buffer
     * @key the key for the pseudorandom function
     * @keylen the size in bytes of the key
     */
    int (*prf)(unsigned char* out,
               uint16_t outlen,
               const unsigned char* in,
               uint16_t inlen,
               const unsigned char* key,
               uint16_t keylen);
};

/**
 * Initialize an :xtt_crypto_hmac: buffer for use with a particular
 * algorithm.
 *
 * @hmac the buffer to initialize
 * @ops the algorithm
 */
inline static
void
xtt_crypto_hmac_init(struct xtt_crypto_hmac* hmac,
                     const struct xtt_crypto_hmac_ops* ops) {
    memset(hmac, 0, sizeof(*hmac));
    hmac->len = ops->outlen;
}

#ifdef __cplusplus
}
#endif

#endif
