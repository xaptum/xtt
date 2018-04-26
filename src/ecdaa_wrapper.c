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
#include <xtt/daa_wrapper.h>
#include <xtt/crypto_types.h>

#include <ecdaa.h>
#include <ecdaa-tpm.h>

#include <assert.h>
#include <string.h>

int
xtt_daa_sign_lrswTPM(unsigned char *signature_out,
                     const unsigned char *msg,
                     uint16_t msg_len,
                     const unsigned char *basename,
                     uint16_t basename_len,
                     xtt_daa_credential_lrsw *cred,
                     TPM_HANDLE key_handle,
                     const char *key_password,
                     uint16_t key_password_length,
                     TSS2_TCTI_CONTEXT *tcti_context)
{
    int ret;

    // 1) Create a PRNG.
    struct ecdaa_prng prng;
    ret = ecdaa_prng_init(&prng);
    if (0 != ret) {
        return -1;
    }

    // 2) Deserialize credential.
    struct ecdaa_credential_FP256BN ecdaa_cred;
    assert(sizeof(xtt_daa_credential_lrsw) == ecdaa_credential_FP256BN_length());
    ret = ecdaa_credential_FP256BN_deserialize(&ecdaa_cred, cred->data);
    if (0 != ret) {
        return ret;
    }

    // 3) Create the ecdaa_tpm_context
    struct ecdaa_tpm_context ecdaa_tpm_context;
    ret = ecdaa_tpm_context_init(&ecdaa_tpm_context,
                                 key_handle,
                                 key_password,
                                 key_password_length,
                                 tcti_context);
    if (0 != ret) {
        return ret;
    }

    // 3) Create signature.
    struct ecdaa_signature_FP256BN sig;
    ret = ecdaa_signature_TPM_FP256BN_sign(&sig,
                                           msg,
                                           msg_len,
                                           basename,
                                           basename_len,
                                           &ecdaa_cred,
                                           &prng,
                                           &ecdaa_tpm_context);
    if (0 != ret) {
        return -1;
    }

    // 4) Serialize signature to output buffer.
    assert(sizeof(xtt_daa_signature_lrsw) == ecdaa_signature_FP256BN_with_nym_length());
    ecdaa_signature_FP256BN_serialize(signature_out, &sig, 1);

    return 0;
}

int
xtt_daa_sign_lrsw(unsigned char *signature_out,
                  const unsigned char *msg,
                  uint16_t msg_len,
                  const unsigned char *basename,
                  uint16_t basename_len,
                  xtt_daa_credential_lrsw *cred,
                  xtt_daa_priv_key_lrsw *priv_key)
{
    int ret;

    // 1) Create a PRNG.
    struct ecdaa_prng prng;
    ret = ecdaa_prng_init(&prng);
    if (0 != ret) {
        return -1;
    }

    // 2) Deserialize credential.
    struct ecdaa_credential_FP256BN ecdaa_cred;
    assert(sizeof(xtt_daa_credential_lrsw) == ecdaa_credential_FP256BN_length());
    ret = ecdaa_credential_FP256BN_deserialize(&ecdaa_cred, cred->data);
    if (0 != ret) {
        return ret;
    }

    // 3) Deserialize private key
    struct ecdaa_member_secret_key_FP256BN ecdaa_secret_key;
    assert(sizeof(xtt_daa_priv_key_lrsw) == ecdaa_member_secret_key_FP256BN_length());
    ret = ecdaa_member_secret_key_FP256BN_deserialize(&ecdaa_secret_key, priv_key->data);
    if (0 != ret) {
        return ret;
    }

    // 3) Create signature.
    struct ecdaa_signature_FP256BN sig;
    ret = ecdaa_signature_FP256BN_sign(&sig,
                                       msg,
                                       msg_len,
                                       basename,
                                       basename_len,
                                       &ecdaa_secret_key,
                                       &ecdaa_cred,
                                       &prng);
    if (0 != ret) {
        return -1;
    }

    // 4) Serialize signature to output buffer.
    assert(sizeof(xtt_daa_signature_lrsw) == ecdaa_signature_FP256BN_with_nym_length());
    ecdaa_signature_FP256BN_serialize(signature_out, &sig, 1);

    return 0;
}

int
xtt_daa_verify_lrsw(unsigned char *signature,
                    unsigned char* msg,
                    uint16_t msg_len,
                    unsigned char *basename,
                    uint16_t basename_len,
                    xtt_daa_group_pub_key_lrsw* gpk)
{
    // 1) Deserialize signature.
    struct ecdaa_signature_FP256BN ecdaa_sig;
    assert(sizeof(xtt_daa_signature_lrsw) == ecdaa_signature_FP256BN_with_nym_length());
    if (0 != ecdaa_signature_FP256BN_deserialize(&ecdaa_sig, signature, 1)) {
        return -1;
    }

    // 2) Deserialize gpk.
    struct ecdaa_group_public_key_FP256BN ecdaa_gpk;
    assert(sizeof(xtt_daa_group_pub_key_lrsw) == ecdaa_group_public_key_FP256BN_length());
    if (0 != ecdaa_group_public_key_FP256BN_deserialize(&ecdaa_gpk, gpk->data)) {
        return -1;
    }

    // TODO: Actually take rev lists as params to this function.
    struct ecdaa_revocations_FP256BN revocations;
    revocations.sk_list = NULL;
    revocations.sk_length = 0;
    revocations.bsn_list = NULL;
    revocations.bsn_length = 0;

    // 3) Verify signature
    int verify_ret = ecdaa_signature_FP256BN_verify(&ecdaa_sig,
                                                    &ecdaa_gpk,
                                                    &revocations,
                                                    msg,
                                                    msg_len,
                                                    basename,
                                                    basename_len);
    if (0 != verify_ret)
        return verify_ret;

    return 0;
}

xtt_return_code_type
xtt_daa_access_pseudonym_in_serialized(unsigned char **raw_pseudonym,
                                       uint16_t *raw_pseudonym_length, 
                                       unsigned char *serialized_signature_in)
{
    uint32_t raw_pseudonym_length_32;
    ecdaa_signature_FP256BN_access_pseudonym_in_serialized(raw_pseudonym,
                                                           &raw_pseudonym_length_32, 
                                                           serialized_signature_in);
    if (raw_pseudonym_length_32 <= UINT16_MAX) {
        *raw_pseudonym_length = raw_pseudonym_length_32;
        return XTT_RETURN_SUCCESS;
    } else {
        return XTT_RETURN_UINT16_OVERFLOW;
    }
}
