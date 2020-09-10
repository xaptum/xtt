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

#include "xtt/crypto.h"
#include "xtt/crypto_wrapper.h"

/** Key Exchange Ops **/
static struct xtt_crypto_kx_ops x25519_ops =
    {
     .public_len = sizeof(xtt_crypto_x25519_public),
     .shared_len = sizeof(xtt_crypto_x25519_shared),
     .keypair  = xtt_crypto_kx_x25519_keypair,
     .exchange = xtt_crypto_kx_x25519_exchange
    };

/** AEAD  Ops **/
static struct xtt_crypto_aead_ops aes256gcm_ops =
    {
     .nonce_len = sizeof(xtt_crypto_aes256gcm_nonce),
     .mac_len = sizeof(xtt_crypto_aes256gcm_mac),
     .key_len = sizeof(xtt_crypto_aes256gcm_key),
     .encrypt = xtt_crypto_aead_aes256gcm_encrypt,
     .decrypt = xtt_crypto_aead_aes256gcm_decrypt
    };

static struct xtt_crypto_aead_ops chacha20poly1305_ops =
    {
     .nonce_len = sizeof(xtt_crypto_chacha20poly1305_nonce),
     .mac_len = sizeof(xtt_crypto_chacha20poly1305_mac),
     .key_len = sizeof(xtt_crypto_chacha20poly1305_key),
     .encrypt = xtt_crypto_aead_chacha20poly1305_encrypt,
     .decrypt = xtt_crypto_aead_chacha20poly1305_decrypt
    };

/** HMAC Ops **/
static struct xtt_crypto_hmac_ops sha512_ops =
    {
     .outlen = sizeof(xtt_crypto_sha512),
     .hash = xtt_crypto_hash_sha512,
     .prf  = xtt_crypto_prf_sha512,
    };

static struct xtt_crypto_hmac_ops blake2b_ops =
    {
     .outlen = sizeof(xtt_crypto_blake2b),
     .hash = xtt_crypto_hash_blake2b,
     .prf  = xtt_crypto_prf_blake2b,
    };

/** Auth Ops **/
static struct xtt_crypto_auth_ops ecdsa_p256_ops =
    {
     .pub_len = sizeof(xtt_crypto_ecdsa_p256_public),
     .sig_len = sizeof(xtt_cyrpto_ecdsa_p256_sig),
     .generate = xtt_crypto_auth_ecdsa_p256_generate,
     .sign  = xtt_crypto_auth_ecdsa_p256_sign,
     .verify = xtt_crypto_auth_ecdsa_p256_verify,
     .compare = xtt_crypto_auth_ecdsa_p256_compare,
    };

static struct xtt_crypto_auth_ops ecdsa_p256_tpm_ops =
    {
     .pub_len = sizeof(xtt_crypto_ecdsa_p256_public),
     .sig_len = sizeof(xtt_cyrpto_ecdsa_p256_sig),
     .generate = xtt_crypto_auth_ecdsa_p256_tpm_generate,
     .sign  = xtt_crypto_auth_ecdsa_p256_tpm_sign,
     .verify = xtt_crypto_auth_ecdsa_p256_verify,
     .compare = xtt_crypto_auth_ecdsa_p256_compare,
    };

/**
  * A array of :xtt_suite_ops: indexed by the :xtt_suite_spec:
  * enum. Each instance points to the default implementations of the
  * algorithms for that suite spec.
  */
static
struct xtt_suite_ops xtt_suite_ops[] =
    {
     { // Suite Spec 0 is undefined
     },
     { // XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512
      .kx   = &x25519_ops,
      .aead = &chacha20poly1305_ops,
      .hmac = &sha512_ops
     },
     { // XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B
      .kx   = &x25519_ops,
      .aead = &chacha20poly1305_ops,
      .hmac = &blake2b_ops
     },
     { // XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512
      .kx   = &x25519_ops,
      .aead = &aes256gcm_ops,
      .hmac = &sha512_ops
     },
     { // XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B
      .kx   = &x25519_ops,
      .aead = &aes256gcm_ops,
      .hmac = &blake2b_ops
     }
    };

const struct xtt_suite_ops*
xtt_suite_ops_get(xtt_suite_spec suite_spec)
{
    if (suite_spec < 1)
        return NULL;

    if (suite_spec > 4)
        return NULL;

    return &xtt_suite_ops[suite_spec];
}
