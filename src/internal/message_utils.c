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

#include "message_utils.h"
#include "byte_utils.h"

#include <assert.h>

const uint16_t xtt_common_header_length = 4;  // Type(1) + Length(2) + Version(1)

xtt_msg_type_raw*
xtt_access_msg_type(const unsigned char* msg_start)
{
    /* No need to check version.
     * This field MUST always be the first field, regardless of version */

    return (xtt_msg_type_raw*)(msg_start);
}

unsigned char*
xtt_access_length(const unsigned char* msg_start)
{
    /* No need to check version.
     * This field MUST always be the second field, regardless of version */

    return (unsigned char*)(msg_start
                            + sizeof(xtt_msg_type_raw));
}


xtt_version_raw*
xtt_access_version(const unsigned char* msg_start)
{
    /* No need to check version.
     * This field MUST always be the third field, regardless of version */

    return (xtt_version_raw*)(msg_start
                               + sizeof(xtt_length)
                               + sizeof(xtt_msg_type_raw));
}

uint16_t xtt_clientinit_length(xtt_version version,
                               xtt_suite_spec suite_spec,
                               const struct xtt_suite_ops* suite_ops)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_msg_type_raw)
                           + sizeof(xtt_length)
                           + sizeof(xtt_version_raw)
                           + sizeof(xtt_suite_spec_raw)
                           + sizeof(xtt_signing_nonce)
                           + suite_ops->kx->public_len;
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_clientinit_access_suite_spec(const unsigned char* msg_start,
                                 xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                          + sizeof(xtt_msg_type_raw)
                                          + sizeof(xtt_length)
                                          + sizeof(xtt_version_raw));
    }

    assert(0);
    return NULL;
}

xtt_signing_nonce* xtt_clientinit_access_nonce(const unsigned char* msg_start,
                                               xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (xtt_signing_nonce*)(msg_start
                                         + sizeof(xtt_msg_type_raw)
                                         + sizeof(xtt_length)
                                         + sizeof(xtt_version_raw)
                                         + sizeof(xtt_suite_spec_raw));
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_clientinit_access_ecdhe_key(const unsigned char* msg_start,
                                xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                    + sizeof(xtt_msg_type_raw)
                                    + sizeof(xtt_length)
                                    + sizeof(xtt_version_raw)
                                    + sizeof(xtt_suite_spec_raw)
                                    + sizeof(xtt_signing_nonce));
    }

    assert(0);
    return NULL;
}

uint16_t xtt_serverinitandattest_unencrypted_part_length(xtt_version version,
                                                         xtt_suite_spec suite_spec,
                                                         const struct xtt_suite_ops* suite_ops)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_msg_type_raw)
                           + sizeof(xtt_length)
                           + sizeof(xtt_version_raw)
                           + sizeof(xtt_suite_spec_raw)
                           + suite_ops->kx->public_len
                           + sizeof(xtt_server_cookie);
            }
    }

    assert(0);
    return 0;
}

uint16_t xtt_serverinitandattest_encrypted_part_length(xtt_version version,
                                                      xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return xtt_server_certificate_length(suite_spec)
                           + sizeof(xtt_ecdsap256_signature);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_serverinitandattest_total_length(xtt_version version,
                                     xtt_suite_spec suite_spec,
                                     const struct xtt_suite_ops* suite_ops)
{
    uint16_t body_length = xtt_serverinitandattest_unencrypted_part_length(version,
                                                                           suite_spec,
                                                                           suite_ops)
        + xtt_serverinitandattest_encrypted_part_length(version, suite_spec);

    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                    return body_length + sizeof(xtt_chacha_mac);
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return body_length + sizeof(xtt_aes256_mac);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_serverinitandattest_uptosignature_length(xtt_version version,
                                             xtt_suite_spec suite_spec,
                                             const struct xtt_suite_ops* suite_ops)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return xtt_serverinitandattest_unencrypted_part_length(version,
                                                                           suite_spec,
                                                                           suite_ops)
                           + xtt_server_certificate_length(suite_spec);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_serverinitandattest_encrypted_part_uptosignature_length(xtt_version version,
                                                           xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return xtt_server_certificate_length(suite_spec);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_serverinitandattest_uptocookie_length(xtt_version version,
                                          xtt_suite_spec suite_spec,
                                          const struct xtt_suite_ops* suite_ops)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_msg_type_raw)
                           + sizeof(xtt_length)
                           + sizeof(xtt_version_raw)
                           + sizeof(xtt_suite_spec_raw)
                           + suite_ops->kx->public_len;
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_serverinitandattest_access_suite_spec(const unsigned char* msg_start,
                                          xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                           + sizeof(xtt_msg_type_raw)
                                           + sizeof(xtt_length)
                                           + sizeof(xtt_version_raw));
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_serverinitandattest_access_ecdhe_key(const unsigned char* msg_start,
                                         xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                    + sizeof(xtt_msg_type_raw)
                                    + sizeof(xtt_length)
                                    + sizeof(xtt_version_raw)
                                    + sizeof(xtt_suite_spec_raw));
    }

    assert(0);
    return NULL;
}

xtt_server_cookie*
xtt_serverinitandattest_access_server_cookie(const unsigned char* msg_start,
                                             xtt_version version,
                                             xtt_suite_spec suite_spec,
                                             const struct xtt_suite_ops* suite_ops)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return (xtt_server_cookie*)(msg_start
                                                  + sizeof(xtt_msg_type_raw)
                                                  + sizeof(xtt_length)
                                                  + sizeof(xtt_version_raw)
                                                  + sizeof(xtt_suite_spec_raw)
                                                  + suite_ops->kx->public_len);
            }
    }

    assert(0);
    return NULL;
}

struct xtt_server_certificate_raw_type*
xtt_encrypted_serverinitandattest_access_certificate(const unsigned char* encrypted_start,
                                                     xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (struct xtt_server_certificate_raw_type*)(encrypted_start);
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_encrypted_serverinitandattest_access_signature(const unsigned char* encrypted_start,
                                                  xtt_version version,
                                                  xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return (unsigned char*)(encrypted_start
                                            + xtt_server_certificate_length(suite_spec));
            }
    }

    assert(0);
    return NULL;
}

uint16_t xtt_identityclientattest_unencrypted_part_length(xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return sizeof(xtt_msg_type_raw)
                   + sizeof(xtt_length)
                   + sizeof(xtt_version_raw)
                   + sizeof(xtt_suite_spec_raw)
                   + sizeof(xtt_server_cookie);
    }

    assert(0);
    return 0;
}

uint16_t xtt_identityclientattest_encrypted_part_length(xtt_version version,
                                                        xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_ecdsap256_pub_key)
                           + sizeof(xtt_ecdsap256_signature)
                           + sizeof(xtt_group_id)
                           + sizeof(xtt_identity_type)
                           + sizeof(xtt_daa_signature_lrsw);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_identityclientattest_total_length(xtt_version version,
                                      xtt_suite_spec suite_spec)
{
    uint16_t body_length = xtt_identityclientattest_unencrypted_part_length(version)
        + xtt_identityclientattest_encrypted_part_length(version, suite_spec);

    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                    return body_length + sizeof(xtt_chacha_mac);
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return body_length + sizeof(xtt_aes256_mac);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_identityclientattest_uptofirstsignature_length(xtt_version version,
                                                   xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_msg_type_raw)
                           + sizeof(xtt_length)
                           + sizeof(xtt_version_raw)
                           + sizeof(xtt_suite_spec_raw)
                           + sizeof(xtt_server_cookie)
                           + sizeof(xtt_ecdsap256_pub_key)
                           + sizeof(xtt_group_id)
                           + sizeof(xtt_identity_type);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_identityclientattest_encrypted_part_uptofirstsignature_length(xtt_version version,
                                                                  xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_ecdsap256_pub_key)
                           + sizeof(xtt_group_id)
                           + sizeof(xtt_identity_type);
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_identityclientattest_access_suite_spec(const unsigned char *msg_start,
                                           xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                    + sizeof(xtt_msg_type_raw)
                                    + sizeof(xtt_length)
                                    + sizeof(xtt_version_raw));
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_identityclientattest_access_servercookie(const unsigned char *msg_start,
                                             xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                    + sizeof(xtt_msg_type_raw)
                                    + sizeof(xtt_length)
                                    + sizeof(xtt_version_raw)
                                    + sizeof(xtt_suite_spec_raw));
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_encrypted_identityclientattest_access_longtermkey(const unsigned char *encrypted_start,
                                                      xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)encrypted_start;
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_encrypted_identityclientattest_access_gid(const unsigned char *encrypted_start,
                                              xtt_version version,
                                              xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return (unsigned char*)(encrypted_start
                                            + sizeof(xtt_ecdsap256_pub_key));
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_encrypted_identityclientattest_access_id(const unsigned char *encrypted_start,
                                             xtt_version version,
                                             xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return (unsigned char*)(encrypted_start
                                            + sizeof(xtt_ecdsap256_pub_key)
                                            + sizeof(xtt_group_id));
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_encrypted_identityclientattest_access_longtermsignature(const unsigned char *encrypted_start,
                                                            xtt_version version,
                                                            xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return (unsigned char*)(encrypted_start
                                            + sizeof(xtt_ecdsap256_pub_key)
                                            + sizeof(xtt_group_id)
                                            + sizeof(xtt_identity_type));
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_encrypted_identityclientattest_access_daasignature(const unsigned char *encrypted_start,
                                                       xtt_version version,
                                                       xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return (unsigned char*)(encrypted_start
                                            + sizeof(xtt_ecdsap256_pub_key)
                                            + sizeof(xtt_group_id)
                                            + sizeof(xtt_identity_type)
                                            + sizeof(xtt_ecdsap256_signature));
            }
    }

    assert(0);
    return 0;
}

uint16_t xtt_identityserverfinished_unencrypted_part_length(xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return sizeof(xtt_msg_type_raw)
                   + sizeof(xtt_length)
                   + sizeof(xtt_version_raw)
                   + sizeof(xtt_suite_spec_raw);
    }

    assert(0);
    return 0;
}

uint16_t xtt_identityserverfinished_encrypted_part_length(xtt_version version,
                                                          xtt_suite_spec suite_spec)
{
    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return sizeof(xtt_identity_type)
                           + sizeof(xtt_ecdsap256_pub_key);
            }
    }

    assert(0);
    return 0;
}

uint16_t
xtt_identityserverfinished_total_length(xtt_version version,
                                        xtt_suite_spec suite_spec)
{
    uint16_t body_length = xtt_identityserverfinished_unencrypted_part_length(version)
        + xtt_identityserverfinished_encrypted_part_length(version, suite_spec);

    switch (version) {
        case XTT_VERSION_ONE:
            switch (suite_spec) {
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
                    return body_length + sizeof(xtt_chacha_mac);
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
                case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
                    return body_length + sizeof(xtt_aes256_mac);
            }
    }

    assert(0);
    return 0;
}

unsigned char*
xtt_identityserverfinished_access_suite_spec(const unsigned char *msg_start,
                                             xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(msg_start
                                    + sizeof(xtt_msg_type_raw)
                                    + sizeof(xtt_length)
                                    + sizeof(xtt_version_raw));
    }

    assert(0);
    return NULL;
}

/* encrypted_start = part of message _after_ the additional data */
unsigned char*
xtt_encrypted_identityserverfinished_access_id(const unsigned char *encrypted_start,
                                               xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)encrypted_start;
    }

    assert(0);
    return NULL;
}

unsigned char*
xtt_encrypted_identityserverfinished_access_longtermkey(const unsigned char *encrypted_start,
                                                        xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (unsigned char*)(encrypted_start
                                    + sizeof(xtt_identity_type));
    }

    assert(0);
    return 0;
}

uint16_t xtt_record_unencrypted_header_length(xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return sizeof(xtt_msg_type_raw)
                   + sizeof(xtt_length)
                   + sizeof(xtt_version_raw)
                   + sizeof(xtt_session_id)
                   + sizeof(xtt_sequence_number);
    }

    assert(0);
    return 0;
}

uint16_t xtt_record_encrypted_header_length(xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return sizeof(xtt_encapsulated_payload_type_raw);
    }

    assert(0);
    return 0;
}
xtt_session_id* xtt_record_access_session_id(const unsigned char* msg_start,
                                             xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (xtt_session_id*)(msg_start
                                      + sizeof(xtt_msg_type_raw)
                                      + sizeof(xtt_length)
                                      + sizeof(xtt_version_raw));
    }

    assert(0);
    return NULL;
}

xtt_sequence_number*
xtt_record_access_sequence_num(const unsigned char* msg_start,
                               xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (xtt_sequence_number*)(msg_start
                                                + sizeof(xtt_msg_type_raw)
                                                + sizeof(xtt_length)
                                                + sizeof(xtt_version_raw)
                                                + sizeof(xtt_session_id));
    }

    assert(0);
    return NULL;
}

xtt_encapsulated_payload_type_raw*
xtt_encrypted_payload_access_encapsulated_payload_type(const unsigned char* encrypted_start,
                                                      xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (xtt_encapsulated_payload_type_raw*)(encrypted_start);
    }

    assert(0);
    return NULL;
}

unsigned char* xtt_encrypted_payload_access_payload(const unsigned char* encrypted_start,
                                                   xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return (xtt_encapsulated_payload_type_raw*)(encrypted_start
                                                         + sizeof(xtt_encapsulated_payload_type_raw));
    }

    assert(0);
    return NULL;
}

uint16_t
xtt_error_msg_length(xtt_version version)
{
    switch (version) {
        case XTT_VERSION_ONE:
            return sizeof(xtt_msg_type_raw)
                   + sizeof(xtt_length)
                   + sizeof(xtt_version_raw);
    }

    assert(0);
    return 0;
}
