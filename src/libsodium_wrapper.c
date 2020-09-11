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

#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>

#include <sodium.h>

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/random.h>
#endif

#include <assert.h>
#include <string.h>

/* Nb. Many (most) of the current LibSodium implementations of the functions used here
 * always return 0.
 * Thus, we just blindly return their return value, since we have no context to parse the codes.
 */

int xtt_crypto_initialize_crypto()
{
    int init_ret;
#if defined(__linux__) && defined(RNDGETENTCNT)
    int rand_fd;
    int ent_count;

    if ((rand_fd = open("/dev/random", O_RDONLY)) != -1) {
        if (ioctl(rand_fd, RNDGETENTCNT, &ent_count) == 0 && ent_count < 160) {
            return XTT_RETURN_INSUFFICIENT_ENTROPY;
        }

        (void) close(rand_fd);
    }
    /* TODO: Check entropy on other platforms */
#endif

    init_ret = sodium_init();
    if (init_ret == -1) {
        return XTT_RETURN_BAD_INIT;
    } else {    /* Can also include init_ret == 1, indicating libsodium already initialized */
        return 0;
    }
}

int xtt_crypto_memcmp(const unsigned char *one, const unsigned char *two, uint16_t length)
{
    return sodium_memcmp(one, two, length);
}

void xtt_crypto_secure_clear(unsigned char* memory, uint16_t memory_length)
{
    sodium_memzero(memory, memory_length);
}

void xtt_crypto_get_random(unsigned char* buffer, uint16_t buffer_length)
{
    // Libsodium makes sure any requests (of any length) always succeed
    // (i.e. they handle EAGAIN or EINTR for getrandom).
    // If there is a fatal problem, they die loudly.
    randombytes_buf(buffer, buffer_length);
}

int xtt_crypto_kx_x25519_keypair(struct xtt_crypto_kx_public* public_key,
                                 struct xtt_crypto_kx_secret* secret_key)
{
    public_key->len = sizeof(xtt_crypto_x25519_public);
    secret_key->len = sizeof(xtt_crypto_x25519_secret);

    randombytes_buf(&secret_key->buf, secret_key->len);
    return crypto_scalarmult_base(&public_key->buf, &secret_key->buf);
}

int xtt_crypto_kx_x25519_exchange(struct xtt_crypto_kx_shared* shared,
                                  const struct xtt_crypto_kx_public* other_public,
                                  const struct xtt_crypto_kx_secret* my_secret)
{
    shared->len = sizeof(xtt_crypto_x25519_shared);

    if (0 != crypto_scalarmult(&shared->buf, &my_secret->buf,
                               &other_public->buf))
        return XTT_RETURN_DIFFIE_HELLMAN;

    if (sodium_is_zero(&shared->buf, shared->len))
        return XTT_RETURN_DIFFIE_HELLMAN;

    return 0;
}

int xtt_crypto_aead_chacha20poly1305_encrypt(unsigned char* cipher,
                                             const unsigned char* msg,
                                             uint16_t msglen,
                                             const unsigned char* ad,
                                             uint16_t adlen,
                                             const struct xtt_crypto_aead_nonce* nonce,
                                             const struct xtt_crypto_aead_key* key)
{
    return crypto_aead_chacha20poly1305_ietf_encrypt(cipher, NULL,
                                                     msg, msglen,
                                                     ad, adlen,
                                                     NULL, &nonce->buf,
                                                     &key->buf);
}

int xtt_crypto_aead_chacha20poly1305_decrypt(unsigned char* msg,
                                             const unsigned char* cipher,
                                             uint16_t cipherlen,
                                             const unsigned char* ad,
                                             uint16_t adlen,
                                             const struct xtt_crypto_aead_nonce* nonce,
                                             const struct xtt_crypto_aead_key* key)
{
    return crypto_aead_chacha20poly1305_ietf_decrypt(msg, NULL,
                                                     NULL,
                                                     cipher, cipherlen,
                                                     ad, adlen,
                                                     &nonce->buf,
                                                     &key->buf);
}

int xtt_crypto_aead_aes256gcm_encrypt(unsigned char* cipher,
                                      const unsigned char* msg,
                                      uint16_t msglen,
                                      const unsigned char* ad,
                                      uint16_t adlen,
                                      const struct xtt_crypto_aead_nonce* nonce,
                                      const struct xtt_crypto_aead_key* key)
{
    return crypto_aead_aes256gcm_encrypt(cipher, NULL,
                                         msg, msglen,
                                         ad, adlen,
                                         NULL, &nonce->buf,
                                         &key->buf);
}

int xtt_crypto_aead_aes256gcm_decrypt(unsigned char* msg,
                                      const unsigned char* cipher,
                                      uint16_t cipherlen,
                                      const unsigned char* ad,
                                      uint16_t adlen,
                                      const struct xtt_crypto_aead_nonce* nonce,
                                      const struct xtt_crypto_aead_key* key)
{
    return crypto_aead_aes256gcm_decrypt(msg, NULL,
                                         NULL,
                                         cipher, cipherlen,
                                         ad, adlen,
                                         &nonce->buf,
                                         &key->buf);
}

int xtt_crypto_hash_sha256(struct xtt_crypto_hmac* out,
                           const unsigned char* in,
                           uint16_t inlen)
{
    out->len = sizeof(xtt_crypto_sha256);

    crypto_hash_sha256_state h;

    if (0 != crypto_hash_sha256_init(&h))
        return -1;
    if (0 != crypto_hash_sha256_update(&h, in, inlen))
        return -1;
    if (0 != crypto_hash_sha256_final(&h, &out->buf))
        return -1;

    return 0;
}

int xtt_crypto_hash_sha512(struct xtt_crypto_hmac* out,
                           const unsigned char* in,
                           uint16_t inlen)
{
    out->len = sizeof(xtt_crypto_sha512);

    crypto_hash_sha512_state h;

    if (0 != crypto_hash_sha512_init(&h))
        return -1;
    if (0 != crypto_hash_sha512_update(&h, in, inlen))
        return -1;
    if (0 != crypto_hash_sha512_final(&h, &out->buf))
        return -1;

    return 0;
}

int xtt_crypto_hash_blake2b(struct xtt_crypto_hmac* out,
                            const unsigned char* in,
                            uint16_t inlen)
{
    out->len = sizeof(xtt_crypto_blake2b);

    crypto_generichash_blake2b_state h;

    if (0 != crypto_generichash_blake2b_init(&h,
                                             NULL,
                                             0,
                                             out->len))
        return -1;
    if (0 != crypto_generichash_blake2b_update(&h, in, inlen))
        return -1;
    if (0 != crypto_generichash_blake2b_final(&h,
                                              &out->buf,
                                              out->len))
        return -1;

    return 0;
}

int xtt_crypto_prf_sha512(unsigned char* out,
                          uint16_t out_len,
                          const unsigned char* in,
                          uint16_t in_len,
                          const unsigned char* key,
                          uint16_t key_len)
{
    crypto_auth_hmacsha512_state h;
    unsigned char buffer[crypto_hash_sha512_BYTES];

    if (out_len > crypto_hash_sha512_BYTES)
        return -1;
    if (0 != crypto_auth_hmacsha512_init(&h, key, key_len))
        return -1;
    if (0 != crypto_auth_hmacsha512_update(&h, in, in_len))
        return -1;
    if (0 != crypto_auth_hmacsha512_final(&h, buffer))
        return -1;

    memcpy(out, buffer, out_len);

    return 0;
}

int xtt_crypto_prf_blake2b(unsigned char* out,
                           uint16_t out_len,
                           const unsigned char* in,
                           uint16_t in_len,
                           const unsigned char* key,
                           uint16_t key_len)
{
    crypto_generichash_blake2b_state h;

    if (out_len > crypto_generichash_blake2b_BYTES_MAX)
        return -1;
    if (0 != crypto_generichash_blake2b_init(&h,
                                             key,
                                             key_len,
                                             out_len))
        return -1;
    if (0 != crypto_generichash_blake2b_update(&h, in, in_len))
        return -1;
    if (0 != crypto_generichash_blake2b_final(&h,
                                              out,
                                              out_len))
        return -1;

    return 0;
}
