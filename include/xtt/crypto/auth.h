/******************************************************************************
 *
 * Copyright 2020 Xaptum, Inc.
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

#ifndef XTT_CRYPTO_AUTH_H
#define XTT_CRYPTO_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

/**
 * Fixed sized buffers for specific authentication algorithms.
 *
 * They are used to ensure that the :xtt_crypto_auth_XXX: generic
 * buffers are large enough for any authentication type.
 */
typedef struct {unsigned char data[32];} xtt_crypto_ecdsa_p256_public;
typedef struct {unsigned char data[32];} xtt_crypto_ecdsa_p256_private;
typedef struct {unsigned char data[32];} xtt_crypto_ecdsa_p256_sig;

#ifdef USE_TPM
typedef struct {
    TSS2_TCTI_CONTEXT *tcti_context;

    TPMI_RH_HIERARHCY hierarchy;
    char hierarchy_password[MAX_TPM_PASSWORD_LENGTH];
    size_t hierarchy_password_len;

    TPM2_HANDLE parent_handle;
    struct xtpm_key longterm_private_key_tpm;
} xtt_crypto_ecdsa_p256_tpm_private;
#endif

/**
 * Generic buffer holding a public key for authentication. The buffer
 * can be sized to hold the public key of any authentication algorithm
 * supported by XTT.
 *
 * Call :xtt_crypto_auth_public_set() to initialize the public key from
 * a char buffer.
 *
 * @buf the first byte of the key
 * @len the size in bytes of the key
 */
struct xtt_crypto_auth_public {
    union {
        unsigned char buf;
        xtt_crypto_ecdsa_p256_public ecdsa_p256;
    };
    uint16_t len;
};

/**
 * Generic structure holding a private key for authentication.
 *
 * @buf the first byte of the key
 * @len the size in bytes of the key
 */
struct xtt_crypto_auth_private {
    union {
        unsigned char buf;
        xtt_crypto_ecdsa_p256_private ecdsa_p256;
#ifdef USE_TPM
        xtt_crypto_ecdsa_p256_tpm_private ecdsa_p256_tpm;
#endif
    };
};

/**
 * Generic buffer holding a public key for authentication. The buffer
 * can be sized to hold the public key of any authentication algorithm
 * supported by XTT.
 *
 * Call :xtt_crypto_auth_public_set() to initialize the public key from
 * a char buffer.
 *
 * @buf the first byte of the key
 * @len the size in bytes of the key
 */
struct xtt_crypto_auth_public {
    union {
        unsigned char buf;
        xtt_crypto_ecdsa_p256_public ecdsa_p256;
    };
    uint16_t len;
};

/**
 * Set the value of an :xtt_crypto_auth_public: key.
 *
 * @public_key the public key to set
 * @buf the buffer holding the value
 * @buflen the size in bytes of value
 */
inline static
void
xtt_crypto_auth_public_set(struct xtt_crypto_auth_public* public_key,
                           unsigned char* buf,
                           uint16_t buflen)
{
    public_key->len = buflen;
    memcpy(&public_key->buf, buf, public_key->len);
}

/**
 * A generic interface for an authentication algorithm.
 */
struct xtt_crypto_auth_ops {
    /**
     * The size in bytes of the public key.
     */
    uint16_t pub_len;

    /**
     * The size in bytes of the signature.
     */
    uint16_t sig_len;

    /**
     * Generates a new key pair.
     *
     * @private_key the destination for the private key
     * @public_key the destination for the public key
     */
    int (*generate)(struct xtt_crypto_auth_private* private_key,
                    struct xtt_crypto_auth_public* public_key);

    /**
     * Signs the message using the provided private key.
     *
     * @sig the destination for the signature
     * @msg the message to sign
     * @msglen the size in bytes of the message
     * @private_key the private key
     */
    int (*sign)(unsigned char* sig,
                const unsigned char* msg,
                uint16_t msglen,
                const struct xtt_crypto_auth_private* private_key);

    /**
     * Computes the shared secret.
     *
     * @shared the destination for the shared secret
     * @other_public the other party's public key
     * @my_secret my secret key
     */
    int (*verify)(const unsigned char* sig,
                  const unsigned char* msg,
                  uint16_t msglen,
                  const struct xtt_crypto_auth_public* public_key);

    /**
     * Returns 0 if the provided keys are equivalent.
     *
     * @key1 the first key to compare
     * @key2 the second key to compare
     */
    int (*compare)(const struct xtt_crypto_auth_public* key1,
                   const struct xtt_crypto_auth_public* key2);
};

#ifdef __cplusplus
}
#endif

#endif
