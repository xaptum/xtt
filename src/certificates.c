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

#include <xtt/certificates.h>

#include <xtt/crypto_wrapper.h>

#include <assert.h>
#include <string.h>

xtt_return_code_type
xtt_generate_server_certificate_ed25519(unsigned char *cert_out,
                                        xtt_identity_type *servers_id,
                                        xtt_ed25519_pub_key *servers_pub_key,
                                        xtt_certificate_expiry *expiry,
                                        xtt_certificate_root_id *roots_id,
                                        xtt_ed25519_priv_key *roots_priv_key)
{
    struct xtt_server_certificate_raw_type *cert_ptr = (struct xtt_server_certificate_raw_type*)cert_out;

    memcpy(xtt_server_certificate_access_id(cert_ptr),
           servers_id->data,
           sizeof(xtt_identity_type));

    memcpy(xtt_server_certificate_access_expiry(cert_ptr),
           expiry->data,
           sizeof(xtt_certificate_expiry));

    memcpy(xtt_server_certificate_access_rootid(cert_ptr),
           roots_id->data,
           sizeof(xtt_certificate_root_id));

    memcpy(xtt_server_certificate_access_pubkey(cert_ptr),
           servers_pub_key->data,
           sizeof(xtt_ed25519_pub_key));

    unsigned char* root_signature = xtt_server_certificate_access_rootsignature_fromsignaturetype(cert_ptr,
                                                                                                  XTT_SERVER_SIGNATURE_TYPE_ED25519);
    int rc = xtt_crypto_sign_ed25519(root_signature,
                                     cert_out,
                                     xtt_server_certificate_length_uptosignature_fromsignaturetype(XTT_SERVER_SIGNATURE_TYPE_ED25519),
                                     roots_priv_key);
    if (0 != rc)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}

uint16_t
xtt_server_certificate_length_fromsignaturetype(xtt_server_signature_type type)
{
    switch (type) {
        case XTT_SERVER_SIGNATURE_TYPE_ED25519:
            return sizeof(xtt_identity_type)
                       + sizeof(xtt_certificate_expiry)
                       + sizeof(xtt_certificate_root_id)
                       + sizeof(xtt_ed25519_pub_key)
                       + sizeof(xtt_ed25519_signature);
    }

    assert(0);
    return 0;
}

uint16_t
xtt_server_certificate_length(xtt_suite_spec suite_spec)
{
    switch (suite_spec) {
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512:
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B:
        case XTT_X25519_LRSW_ED25519_AES256GCM_SHA512:
        case XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B:
            return xtt_server_certificate_length_fromsignaturetype(XTT_SERVER_SIGNATURE_TYPE_ED25519);
    }

    assert(0);
    return 0;
}

uint16_t
xtt_server_certificate_length_uptosignature_fromsignaturetype(xtt_server_signature_type type)
{
    switch (type) {
        case XTT_SERVER_SIGNATURE_TYPE_ED25519:
            return sizeof(xtt_identity_type)
                       + sizeof(xtt_certificate_expiry)
                       + sizeof(xtt_certificate_root_id)
                       + sizeof(xtt_ed25519_pub_key);
    }

    assert(0);
    return 0;
}

uint16_t
xtt_server_certificate_length_uptosignature(xtt_suite_spec suite_spec)
{
    switch (suite_spec) {
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512:
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B:
        case XTT_X25519_LRSW_ED25519_AES256GCM_SHA512:
        case XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B:
            return xtt_server_certificate_length_uptosignature_fromsignaturetype(XTT_SERVER_SIGNATURE_TYPE_ED25519);
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_server_certificate_access_id(const struct xtt_server_certificate_raw_type *certificate)
{
    return (unsigned char*)(certificate);
}

unsigned char*
xtt_server_certificate_access_expiry(const struct xtt_server_certificate_raw_type *certificate)
{
    return (unsigned char*)(certificate)
                            + sizeof(xtt_identity_type);
}

unsigned char*
xtt_server_certificate_access_rootid(const struct xtt_server_certificate_raw_type *certificate)
{
    return (unsigned char*)(certificate)
                            + sizeof(xtt_identity_type)
                            + sizeof(xtt_certificate_expiry);
}

unsigned char*
xtt_server_certificate_access_pubkey(const struct xtt_server_certificate_raw_type *certificate)
{
    return (unsigned char*)(certificate)
                            + sizeof(xtt_identity_type)
                            + sizeof(xtt_certificate_expiry)
                            + sizeof(xtt_certificate_root_id);
}

unsigned char*
xtt_server_certificate_access_rootsignature_fromsignaturetype(const struct xtt_server_certificate_raw_type *certificate,
                                                              xtt_server_signature_type type)
{
    switch (type) {
        case XTT_SERVER_SIGNATURE_TYPE_ED25519:
            return (unsigned char*)(certificate)
                                    + sizeof(xtt_identity_type)
                                    + sizeof(xtt_certificate_expiry)
                                    + sizeof(xtt_certificate_root_id)
                                    + sizeof(xtt_ed25519_pub_key);
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_server_certificate_access_rootsignature(const struct xtt_server_certificate_raw_type *certificate,
                                            xtt_suite_spec suite_spec)
{
    switch (suite_spec) {
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512:
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B:
        case XTT_X25519_LRSW_ED25519_AES256GCM_SHA512:
        case XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B:
            return xtt_server_certificate_access_rootsignature_fromsignaturetype(certificate, XTT_SERVER_SIGNATURE_TYPE_ED25519);
    }

    assert(0);
    return 0;
}
