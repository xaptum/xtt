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

#ifndef XTT_MESSAGE_UTILS_H
#define XTT_MESSAGE_UTILS_H
#pragma once

#include <xtt/crypto.h>
#include <xtt/crypto_types.h>
#include <xtt/certificates.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const uint16_t xtt_common_header_length;

/* NOTE: These methods take a const pointer to the underlying message buffer,
 * yet return non-const pointers into that buffer.
 * So, beware. */

/* Common header accessors */
xtt_msg_type_raw*
xtt_access_msg_type(const unsigned char* msg_start);

unsigned char*
xtt_access_length(const unsigned char* msg_start);

xtt_version_raw*
xtt_access_version(const unsigned char* msg_start);

/* ClientInit */
uint16_t xtt_clientinit_length(xtt_version version,
                               xtt_suite_spec suite_spec,
                               const struct xtt_suite_ops* suite_ops);

unsigned char*
xtt_clientinit_access_suite_spec(const unsigned char* msg_start,
                                 xtt_version version);

xtt_signing_nonce* xtt_clientinit_access_nonce(const unsigned char* msg_start,
                                                 xtt_version version);

unsigned char*
xtt_clientinit_access_ecdhe_key(const unsigned char* msg_start,
                                xtt_version version);

/* ServerInitAndAttest */
uint16_t xtt_serverinitandattest_unencrypted_part_length(xtt_version version,
                                                         xtt_suite_spec suite_spec,
                                                         const struct xtt_suite_ops* suite_ops);

uint16_t xtt_serverinitandattest_encrypted_part_length(xtt_version version,
                                                       xtt_suite_spec suite_spec);

uint16_t
xtt_serverinitandattest_total_length(xtt_version version,
                                     xtt_suite_spec suite_spec,
                                     const struct xtt_suite_ops* suite_ops);

uint16_t
xtt_serverinitandattest_uptosignature_length(xtt_version version,
                                             xtt_suite_spec suite_spec,
                                             const struct xtt_suite_ops* suite_ops);

uint16_t
xtt_serverinitandattest_encrypted_part_uptosignature_length(xtt_version version,
                                                           xtt_suite_spec suite_spec);

uint16_t
xtt_serverinitandattest_uptocookie_length(xtt_version version,
                                          xtt_suite_spec suite_spec,
                                          const struct xtt_suite_ops* suite_ops);

unsigned char*
xtt_serverinitandattest_access_suite_spec(const unsigned char* msg_start,
                                          xtt_version version);

unsigned char*
xtt_serverinitandattest_access_ecdhe_key(const unsigned char* msg_start,
                                         xtt_version version);

xtt_server_cookie*
xtt_serverinitandattest_access_server_cookie(const unsigned char* msg_start,
                                             xtt_version version,
                                             xtt_suite_spec suite_spec,
                                             const struct xtt_suite_ops* suite_ops);

/* encrypted_start = part of message _after_ the additional data */
struct xtt_server_certificate_raw_type*
xtt_encrypted_serverinitandattest_access_certificate(const unsigned char* encrypted_start,
                                                     xtt_version version);

unsigned char*
xtt_encrypted_serverinitandattest_access_signature(const unsigned char* encrypted_start,
                                                   xtt_version version,
                                                   xtt_suite_spec suite_spec);

/* Identity_ClientAttest accessors */
uint16_t xtt_identityclientattest_unencrypted_part_length(xtt_version version);

uint16_t xtt_identityclientattest_encrypted_part_length(xtt_version version,
                                                        xtt_suite_spec suite_spec);

uint16_t
xtt_identityclientattest_total_length(xtt_version version,
                                      xtt_suite_spec suite_spec,
                                      const struct xtt_suite_ops* suite_ops);

uint16_t
xtt_identityclientattest_uptofirstsignature_length(xtt_version version,
                                                   xtt_suite_spec suite_spec);

uint16_t
xtt_identityclientattest_encrypted_part_uptofirstsignature_length(xtt_version version,
                                                                  xtt_suite_spec suite_spec);

unsigned char*
xtt_identityclientattest_access_suite_spec(const unsigned char *msg_start,
                                           xtt_version version);

unsigned char*
xtt_identityclientattest_access_servercookie(const unsigned char *msg_start,
                                             xtt_version version);

/* encrypted_start = part of message _after_ the additional data */
unsigned char*
xtt_encrypted_identityclientattest_access_longtermkey(const unsigned char *encrypted_start,
                                                      xtt_version version);

unsigned char*
xtt_encrypted_identityclientattest_access_gid(const unsigned char *encrypted_start,
                                              xtt_version version,
                                              xtt_suite_spec suite_spec);

unsigned char*
xtt_encrypted_identityclientattest_access_id(const unsigned char *encrypted_start,
                                             xtt_version version,
                                             xtt_suite_spec suite_spec);

unsigned char*
xtt_encrypted_identityclientattest_access_longtermsignature(const unsigned char *encrypted_start,
                                                            xtt_version version,
                                                            xtt_suite_spec suite_spec);

unsigned char*
xtt_encrypted_identityclientattest_access_daasignature(const unsigned char *encrypted_start,
                                                       xtt_version version,
                                                       xtt_suite_spec suite_spec);

/* Identity_ServerFinished accessors */
uint16_t xtt_identityserverfinished_unencrypted_part_length(xtt_version version);

uint16_t xtt_identityserverfinished_encrypted_part_length(xtt_version version,
                                                          xtt_suite_spec suite_spec);

uint16_t
xtt_identityserverfinished_total_length(xtt_version version,
                                        xtt_suite_spec suite_spec,
                                        const struct xtt_suite_ops* suite_ops);

unsigned char*
xtt_identityserverfinished_access_suite_spec(const unsigned char *msg_start,
                                             xtt_version version);

/* encrypted_start = part of message _after_ the additional data */
unsigned char*
xtt_encrypted_identityserverfinished_access_id(const unsigned char *encrypted_start,
                                               xtt_version version);

unsigned char*
xtt_encrypted_identityserverfinished_access_longtermkey(const unsigned char *encrypted_start,
                                                        xtt_version version);

/* Record accessors */
/* msg_start = beginning of full message */
uint16_t xtt_record_unencrypted_header_length(xtt_version version);

uint16_t xtt_record_encrypted_header_length(xtt_version version);

xtt_session_id* xtt_record_access_session_id(const unsigned char* msg_start,
                                               xtt_version version);

xtt_sequence_number* xtt_record_access_sequence_num(const unsigned char* msg_start,
                                                          xtt_version version);

/* encrypted_start = part of message _after_ the additional data */
xtt_encapsulated_payload_type_raw*
xtt_encrypted_payload_access_encapsulated_payload_type(const unsigned char* encrypted_start,
                                                       xtt_version version);

unsigned char* xtt_encrypted_payload_access_payload(const unsigned char* encrypted_start,
                                                    xtt_version version);

/* XTT_ERROR_MSG */
uint16_t
xtt_error_msg_length(xtt_version version);

#ifdef __cplusplus
}
#endif

#endif
