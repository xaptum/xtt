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

#include "crypto_utils.h"
#include "byte_utils.h"

#include <xtt/crypto_wrapper.h>
#include <xtt/daa_wrapper.h>
#include <xtt/certificates.h>

#include <stddef.h>
#include <string.h>
#include <assert.h>

static
void prepare_nonce(unsigned char* nonce,
                   xtt_sequence_number sequence_number,
                   const unsigned char* iv,
                   uint32_t length);

void copy_dh_pubkey_x25519(unsigned char* out,
                           uint16_t* out_length,
                           const struct xtt_handshake_context* self)
{
    memcpy(out,
           &self->kx_pubkey.buf,
           self->kx_pubkey.len);

    if (NULL != out_length)
        *out_length = self->kx_pubkey.len;
}

int do_diffie_hellman_x25519(unsigned char* shared_secret,
                             const unsigned char* other_pk,
                             const struct xtt_handshake_context* self)
{
    return xtt_crypto_do_x25519_diffie_hellman(shared_secret,
                                               (xtt_x25519_priv_key*)&self->kx_seckey.buf,
                                               (xtt_x25519_pub_key*)other_pk);
}

void copy_longterm_key_ecdsap256(unsigned char* out,
                               uint16_t* out_length,
                               const struct xtt_client_handshake_context* self)
{
    memcpy(out,
           self->longterm_key.ecdsap256.data,
           sizeof(xtt_ecdsap256_pub_key));

    if (NULL != out_length)
        *out_length = sizeof(xtt_ecdsap256_pub_key);
}

int compare_longterm_keys_ecdsap256(unsigned char *other_key,
                                  const struct xtt_client_handshake_context *self)
{
    return xtt_crypto_memcmp(self->longterm_key.ecdsap256.data,
                             other_key,
                             sizeof(xtt_ecdsap256_pub_key));
}

int encrypt_null(unsigned char* ciphertext,
                 uint16_t* ciphertext_len,
                 const unsigned char* message,
                 uint16_t msg_len,
                 const unsigned char* addl_data,
                 uint16_t addl_len,
                 struct xtt_handshake_context *self)
{
    (void)addl_data;
    (void)addl_len;
    (void)self;

    memcpy(ciphertext,
           message,
           msg_len);

    *ciphertext_len = msg_len;

    return 0;
}

int encrypt_chacha(unsigned char* ciphertext,
                   uint16_t* ciphertext_len,
                   const unsigned char* message,
                   uint16_t msg_len,
                   const unsigned char* addl_data,
                   uint16_t addl_len,
                   struct xtt_handshake_context *self)
{
    int ret;
    xtt_chacha_nonce nonce;

    prepare_nonce(nonce.data,
                  self->tx_sequence_num,
                  self->tx_iv.chacha.data,
                  sizeof(nonce));

    self->tx_sequence_num++;

    ret = xtt_crypto_aead_chacha_encrypt(ciphertext,
                                         ciphertext_len,
                                         message,
                                         msg_len,
                                         addl_data,
                                         addl_len,
                                         &nonce,
                                         &self->tx_key.chacha);

    xtt_crypto_secure_clear(nonce.data, sizeof(nonce));

    return ret;
}

int encrypt_aes256(unsigned char* ciphertext,
                   uint16_t* ciphertext_len,
                   const unsigned char* message,
                   uint16_t msg_len,
                   const unsigned char* addl_data,
                   uint16_t addl_len,
                   struct xtt_handshake_context *self)
{
    int ret;
    xtt_aes256_nonce nonce;

    prepare_nonce(nonce.data,
                  self->tx_sequence_num,
                  self->tx_iv.aes256.data,
                  sizeof(nonce));

    self->tx_sequence_num++;

    ret = xtt_crypto_aead_aes256_encrypt(ciphertext,
                                         ciphertext_len,
                                         message,
                                         msg_len,
                                         addl_data,
                                         addl_len,
                                         &nonce,
                                         &self->tx_key.aes256);

    xtt_crypto_secure_clear(nonce.data, sizeof(nonce));

    return ret;
}

int decrypt_null(unsigned char* decrypted,
                 uint16_t* decrypted_len,
                 const unsigned char* ciphertext,
                 uint16_t ciphertext_len,
                 const unsigned char* addl_data,
                 uint16_t addl_len,
                 struct xtt_handshake_context *self)
{
    (void)addl_data;
    (void)addl_len;
    (void)self;

    memcpy(decrypted,
           ciphertext,
           ciphertext_len);

    *decrypted_len = ciphertext_len;

    return 0;
}

int decrypt_chacha(unsigned char* decrypted,
                   uint16_t* decrypted_len,
                   const unsigned char* ciphertext,
                   uint16_t ciphertext_len,
                   const unsigned char* addl_data,
                   uint16_t addl_len,
                   struct xtt_handshake_context *self)
{
    int ret;
    xtt_chacha_nonce nonce;

    prepare_nonce(nonce.data,
                  self->rx_sequence_num,
                  self->rx_iv.chacha.data,
                  sizeof(nonce));

    self->rx_sequence_num++;

    ret = xtt_crypto_aead_chacha_decrypt(decrypted,
                                         decrypted_len,
                                         ciphertext,
                                         ciphertext_len,
                                         addl_data,
                                         addl_len,
                                         &nonce,
                                         &self->rx_key.chacha);

    xtt_crypto_secure_clear(nonce.data, sizeof(nonce));

    return ret;
}

int decrypt_aes256(unsigned char* decrypted,
                   uint16_t* decrypted_len,
                   const unsigned char* ciphertext,
                   uint16_t ciphertext_len,
                   const unsigned char* addl_data,
                   uint16_t addl_len,
                   struct xtt_handshake_context *self)
{
    int ret;
    xtt_aes256_nonce nonce;

    prepare_nonce(nonce.data,
                  self->rx_sequence_num,
                  self->rx_iv.aes256.data,
                  sizeof(nonce));

    self->rx_sequence_num++;

    ret = xtt_crypto_aead_aes256_decrypt(decrypted,
                                         decrypted_len,
                                         ciphertext,
                                         ciphertext_len,
                                         addl_data,
                                         addl_len,
                                         &nonce,
                                         &self->rx_key.aes256);

    xtt_crypto_secure_clear(nonce.data, sizeof(nonce));

    return ret;
}

void read_longterm_key_ecdsap256(struct xtt_server_handshake_context *self,
                               uint16_t* key_length,
                               unsigned char* key_in)
{
    memcpy(self->clients_longterm_key.ecdsap256.data,
           key_in,
           sizeof(xtt_ecdsap256_pub_key));

    if (NULL != key_length)
        *key_length = sizeof(xtt_ecdsap256_pub_key);
}

int verify_server_signature_ecdsap256(const unsigned char *signature,
                                    const unsigned char *msg,
                                    uint16_t msg_len,
                                    const unsigned char *server_public_key)
{
    int ret = xtt_crypto_verify_ecdsap256(signature, msg, msg_len, (xtt_ecdsap256_pub_key*)server_public_key);

    if (0 != ret) {
        return XTT_RETURN_BAD_SERVER_SIGNATURE;
    } else {
        return XTT_RETURN_SUCCESS;
    }
}

int sign_server_ecdsap256(unsigned char *signature_out,
                        const unsigned char *msg,
                        uint16_t msg_len,
                        const struct xtt_server_certificate_context *self)
{
    return xtt_crypto_sign_ecdsap256(signature_out,
                                   msg,
                                   msg_len,
                                   &self->private_key.ecdsap256);
}

int longterm_sign_ecdsap256(unsigned char *signature_out,
                          const unsigned char *msg,
                          uint16_t msg_len,
                          const struct xtt_client_handshake_context *self)
{
    return xtt_crypto_sign_ecdsap256(signature_out,
                                   msg,
                                   msg_len,
                                   &self->longterm_private_key.ecdsap256);
}

int verify_root_ecdsap256(const unsigned char *signature, //equivalent to verify_signature
                        const struct xtt_server_certificate_raw_type *certificate,
                        const struct xtt_server_root_certificate_context *self)
{
    int ret = xtt_crypto_verify_ecdsap256(signature,
                                        (unsigned char*)certificate,
                                        xtt_server_certificate_length_uptosignature_fromsignaturetype(XTT_SERVER_SIGNATURE_TYPE_ECDSAP256),
                                        &self->public_key.ecdsap256);
    if (0 != ret) {
        return XTT_RETURN_BAD_ROOT_SIGNATURE;
    } else {
        return XTT_RETURN_SUCCESS;
    }
}

#ifdef USE_TPM
int sign_lrswTPM(unsigned char *signature_out,
                 const unsigned char *msg,
                 uint16_t msg_len,
                 struct xtt_client_group_context *self)
{
    int rc = xtt_daa_sign_lrswTPM(signature_out,
                                  msg,
                                  msg_len,
                                  self->basename,
                                  self->basename_length,
                                  &self->cred.lrsw,
                                  self->key_handle,
                                  self->key_password,
                                  self->key_password_length,
                                  self->tcti_context);

    if (0 != rc)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}
#endif

int sign_lrsw(unsigned char *signature_out,
              const unsigned char *msg,
              uint16_t msg_len,
              struct xtt_client_group_context *self)
{
    int rc = xtt_daa_sign_lrsw(signature_out,
                               msg,
                               msg_len,
                               self->basename,
                               self->basename_length,
                               &self->cred.lrsw,
                               &self->priv_key.lrsw);

    if (0 != rc)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}

int verify_lrsw(unsigned char *signature,   //equivalent to verify_signature
                unsigned char *msg,
                uint16_t msg_len,
                struct xtt_group_public_key_context *self)
{
    int ret = xtt_daa_verify_lrsw(signature,
                                  msg,
                                  msg_len,
                                  self->basename,
                                  self->basename_length,
                                  &self->gpk.lrsw);

    if (0 != ret) {
        return XTT_RETURN_BAD_CLIENT_SIGNATURE;
    } else {
        return XTT_RETURN_SUCCESS;
    }
}

int copy_pseudonym_lrsw(unsigned char *out,
                        uint16_t *out_length,
                        unsigned char *serialized_signature_in)
{
    unsigned char *raw_pseudonym;
    xtt_return_code_type rc;
    rc = xtt_daa_access_pseudonym_in_serialized(&raw_pseudonym,
                                                out_length,
                                                serialized_signature_in);
    if (XTT_RETURN_SUCCESS != rc) {
        return -1;
    }

    assert(*out_length == sizeof(xtt_daa_pseudonym_lrsw));

    memcpy(out,
           raw_pseudonym,
           *out_length);

    return 0;
}

int copy_in_pseudonym_server_lrsw(struct xtt_server_handshake_context *self,
                                  unsigned char *signature_in)
{
    uint16_t out_length_ignore;
    return copy_pseudonym_lrsw(self->clients_pseudonym.lrsw.data,
                               &out_length_ignore,
                               signature_in);
}

int copy_in_pseudonym_client_lrsw(struct xtt_client_handshake_context *self,
                                  unsigned char *signature_in)
{
    uint16_t out_length_ignore;
    return copy_pseudonym_lrsw(self->pseudonym.lrsw.data,
                               &out_length_ignore,
                               signature_in);
}

void prepare_nonce(unsigned char* nonce,
                   xtt_sequence_number sequence_number,
                   const unsigned char* iv,
                   uint32_t nonce_length)
{
    uint32_t padding_length = nonce_length - sizeof(xtt_sequence_number);
    assert(nonce_length > sizeof(xtt_sequence_number));

    memset(nonce, 0U, padding_length);

    assert(sizeof(xtt_sequence_number) == sizeof(uint32_t));
    long_to_bigendian(sequence_number, nonce + padding_length);

    xor_equals(nonce, iv, nonce_length);
}
