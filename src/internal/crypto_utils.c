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

#ifdef USE_TPM
#include <xaptum-tpm.h>
#include <tss2/tss2_tpm2_types.h>
#endif

#include <stddef.h>
#include <string.h>
#include <assert.h>

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

#ifdef USE_TPM
int longterm_sign_ecdsap256TPM(unsigned char *signature_out,
                               const unsigned char *msg,
                               uint16_t msg_len,
                               const struct xtt_client_handshake_context *self)
{
    TPM2B_DIGEST hash = {};
    struct xtt_crypto_hmac xtt_hash = {};
    if (0 != xtt_crypto_hash_sha256(&xtt_hash, msg, msg_len))
        return XTT_RETURN_CRYPTO;
    memcpy(hash.buffer, &xtt_hash.buf, sizeof(xtt_crypto_sha256));
    hash.size = xtt_hash.len;

    TPMT_SIGNATURE tpm_signature = {};
    if (TSS2_RC_SUCCESS != xtpm_sign(self->tcti_context,
                                     &self->longterm_private_key_tpm,
                                     &hash,
                                     &tpm_signature))
        return XTT_RETURN_CRYPTO;

    memcpy(signature_out,
           &tpm_signature.signature.ecdsa.signatureR.buffer[0],
           tpm_signature.signature.ecdsa.signatureR.size);
    memcpy(&signature_out[tpm_signature.signature.ecdsa.signatureR.size],
           tpm_signature.signature.ecdsa.signatureS.buffer,
           tpm_signature.signature.ecdsa.signatureS.size);

    return XTT_RETURN_SUCCESS;
}
#endif

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

void prepare_aead_nonce(struct xtt_crypto_aead_nonce* nonce,
                        xtt_sequence_number* seqnum,
                        const struct xtt_crypto_aead_nonce* iv)
{
    assert(nonce->len > sizeof(*seqnum));
    assert(sizeof(*seqnum) == sizeof(uint32_t));

    uint32_t padlen = nonce->len - sizeof(*seqnum);
    memset(nonce, 0U, padlen);

    long_to_bigendian(*seqnum, &nonce->buf + padlen);
    *seqnum += 1;

    xor_equals(&nonce->buf, &iv->buf, nonce->len);
}
