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

int xtt_crypto_create_x25519_key_pair(xtt_x25519_pub_key *pub, xtt_x25519_priv_key *priv)
{
    randombytes_buf(priv->data, sizeof(xtt_x25519_priv_key));

    return crypto_scalarmult_base(pub->data, priv->data);
}

int xtt_crypto_do_x25519_diffie_hellman(unsigned char* shared_secret,
                                        const xtt_x25519_priv_key* my_sk,
                                        const xtt_x25519_pub_key* other_pk)
{
    int rc = crypto_scalarmult(shared_secret,
                               my_sk->data,
                               other_pk->data);
    if (sodium_is_zero(shared_secret, crypto_scalarmult_BYTES))
        return XTT_RETURN_DIFFIE_HELLMAN;

    return rc;
}

int xtt_crypto_hash_sha256(unsigned char* out,
                           uint16_t* out_length,
                           const unsigned char* in,
                           uint16_t in_len)
{
    crypto_hash_sha256_state h;

    *out_length = sizeof(xtt_sha256);

    if (0 != crypto_hash_sha256_init(&h))
        return -1;
    if (0 != crypto_hash_sha256_update(&h, in, in_len))
        return -1;
    if (0 != crypto_hash_sha256_final(&h, out))
        return -1;

    return 0;
}

int xtt_crypto_hash_sha512(unsigned char* out,
                           uint16_t* out_length,
                           const unsigned char* in,
                           uint16_t in_len)
{
    crypto_hash_sha512_state h;

    *out_length = sizeof(xtt_sha512);

    if (0 != crypto_hash_sha512_init(&h))
        return -1;
    if (0 != crypto_hash_sha512_update(&h, in, in_len))
        return -1;
    if (0 != crypto_hash_sha512_final(&h, out))
        return -1;

    return 0;
}

int xtt_crypto_hash_blake2b(unsigned char* out,
                            uint16_t* out_length,
                            const unsigned char* in,
                            uint16_t in_len)
{
    crypto_generichash_blake2b_state h;

    *out_length = sizeof(xtt_blake2b);

    if (0 != crypto_generichash_blake2b_init(&h,
                                             NULL,
                                             0,
                                             sizeof(xtt_blake2b)))
        return -1;
    if (0 != crypto_generichash_blake2b_update(&h, in, in_len))
        return -1;
    if (0 != crypto_generichash_blake2b_final(&h,
                                              out,
                                              sizeof(xtt_blake2b)))
        return -1;

    return 0;
}

int xtt_crypto_prf_sha256(unsigned char* out,
                          uint16_t out_len,
                          const unsigned char* in,
                          uint16_t in_len,
                          const unsigned char* key,
                          uint16_t key_len)
{
    crypto_auth_hmacsha256_state h;
    unsigned char buffer[crypto_hash_sha256_BYTES];

    if (out_len > crypto_hash_sha256_BYTES)
        return -1;
    if (0 != crypto_auth_hmacsha256_init(&h, key, key_len))
        return -1;
    if (0 != crypto_auth_hmacsha256_update(&h, in, in_len))
        return -1;
    if (0 != crypto_auth_hmacsha256_final(&h, buffer))
        return -1;

    memcpy(out, buffer, out_len);

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

int xtt_crypto_aead_chacha_encrypt(unsigned char* ciphertext,
                                   uint16_t* ciphertext_len,
                                   const unsigned char* message,
                                   uint16_t msg_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_chacha_nonce* nonce,
                                   const xtt_chacha_key* key)
{
    unsigned long long ciphertext_len_long;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext,
                                                        &ciphertext_len_long,
                                                        message,
                                                        msg_len,
                                                        addl_data,
                                                        addl_len,
                                                        NULL,
                                                        nonce->data,
                                                        key->data);

    if (ciphertext_len_long <= UINT32_MAX) {
        *ciphertext_len = ciphertext_len_long;
        return ret;
    } else {
        return XTT_RETURN_UINT32_OVERFLOW;
    }
}

int xtt_crypto_aead_chacha_decrypt(unsigned char* decrypted,
                                   uint16_t* decrypted_len,
                                   const unsigned char* ciphertext,
                                   uint16_t ciphertext_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_chacha_nonce* nonce,
                                   const xtt_chacha_key* key)
{
    unsigned long long decrypted_len_long;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(decrypted,
                                                        &decrypted_len_long,
                                                        NULL,
                                                        ciphertext,
                                                        ciphertext_len,
                                                        addl_data,
                                                        addl_len,
                                                        nonce->data,
                                                        key->data);

    if (decrypted_len_long <= UINT32_MAX) {
        *decrypted_len = decrypted_len_long;
        return ret;
    } else {
        return XTT_RETURN_UINT32_OVERFLOW;
    }
}

int xtt_crypto_aead_aes256_encrypt(unsigned char* ciphertext,
                                   uint16_t* ciphertext_len,
                                   const unsigned char* message,
                                   uint16_t msg_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_aes256_nonce* nonce,
                                   const xtt_aes256_key* key)
{
    unsigned long long ciphertext_len_long;
    int ret = crypto_aead_aes256gcm_encrypt(ciphertext,
                                            &ciphertext_len_long,
                                            message,
                                            msg_len,
                                            addl_data,
                                            addl_len,
                                            NULL,
                                            nonce->data,
                                            key->data);

    if (ciphertext_len_long <= UINT32_MAX) {
        *ciphertext_len = ciphertext_len_long;
        return ret;
    } else {
        return XTT_RETURN_UINT32_OVERFLOW;
    }
}

int xtt_crypto_aead_aes256_decrypt(unsigned char* decrypted,
                                   uint16_t* decrypted_len,
                                   const unsigned char* ciphertext,
                                   uint16_t ciphertext_len,
                                   const unsigned char* addl_data,
                                   uint16_t addl_len,
                                   const xtt_aes256_nonce* nonce,
                                   const xtt_aes256_key* key)
{
    unsigned long long decrypted_len_long;
    int ret = crypto_aead_aes256gcm_decrypt(decrypted,
                                            &decrypted_len_long,
                                            NULL,
                                            ciphertext,
                                            ciphertext_len,
                                            addl_data,
                                            addl_len,
                                            nonce->data,
                                            key->data);

    if (decrypted_len_long <= UINT32_MAX) {
        *decrypted_len = decrypted_len_long;
        return ret;
    } else {
        return XTT_RETURN_UINT32_OVERFLOW;
    }
}
