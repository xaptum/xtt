/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
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

#ifndef XTT_INTERNAL_ASN1_H
#define XTT_INTERNAL_ASN1_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

extern const unsigned char SEQUENCE_TAG;
extern const unsigned char SET_TAG;
extern const unsigned char INTEGER_TAG;
extern const unsigned char OBJECTIDENTIFIER_TAG;
extern const unsigned char UTCTIME_TAG;
extern const unsigned char BITSTRING_TAG;
extern const unsigned char OCTETSTRING_TAG;
extern const unsigned char CONSTRUCTED_TAG0;
extern const unsigned char CONSTRUCTED_TAG1;

extern const unsigned char COMMONNAME_OID[3];
extern const unsigned char ECDSA_W_SHA256_OID[8];
extern const unsigned char PRIME256V1_OID[8];

extern const unsigned char ECPUBLICKEY_OID[7];

extern const unsigned char ONEASYMMETRICKEY_VERSION;

extern const unsigned char UTF8STRING_ATTRTYPE;

extern const int VALIDITY_YEARS;

enum { UTC_LENGTH = 13 };                                                               // YYMMDDhhssmm'Z'
enum { NAME_LENGTH = 39 };
enum { RAW_PRIVATE_KEY_LENGTH = 32 };
enum { PUBLIC_KEY_LENGTH = 65 };
enum { SIGNATURE_LENGTH = 64 };

enum { serial_num_length = 1 + 1 + 20 };                                                // tag(1) + length(1) + content(20)


enum { ecdsa_w_sha256_oid_length = 2 + 8 };
enum { ecdsap256_algid_length = 1 + 1 + ecdsa_w_sha256_oid_length };

enum { prime256v1_oid_length = 2 + 8 };
enum { ecpublickey_oid_length = 2 + 7 };

enum { name_string_length = 1 + 1 + NAME_LENGTH };                                               // tag(1) + length(1) + content(32)
enum { name_oid_length = 1 + 1 + 3 };                                                   // tag(1) + length(1) + content(3)
enum { name_attr_tandv_length = 1 + 1 + name_oid_length + name_string_length };         // tag(1) + length(1) + name_oid_length + name_string_length
enum { rdn_length = 1 + 1 + name_attr_tandv_length };                                   // tag(1) + length(1) + name_attr_tandv_length
enum { name_length = 1 + 1 + rdn_length };                                              // tag(1) + length(1) + rdn_length

enum { utctime_length = 1 + 1 + UTC_LENGTH };                                           // tag(1) + length(1) + content(13) 'YYMMDDhhssmmZ'
enum { validity_length = 1 + 1 + 2*utctime_length };                                    // tag(1) + length(1) + 2*utctime_length (one for notBefore, other for notAfter)

enum { curve_def_length = 1 + 1 + prime256v1_oid_length + ecpublickey_oid_length };

enum { pubkey_bitstring_length = 1 + 1 + 1 + PUBLIC_KEY_LENGTH };                       // tag(1) + length(1) + padding(1) + content(65)
enum { subjectpublickeyinfo_length = 1 + 1 + curve_def_length + pubkey_bitstring_length };    // tag(1) + length(1) + ecdsa_algid_length + pubkey_bitstring_length

enum { tbs_certificate_length = 1 + 3 + serial_num_length + ecdsap256_algid_length + name_length + validity_length + name_length + subjectpublickeyinfo_length};

enum { signature_algorithm_length = ecdsap256_algid_length };

enum { signature_value_length = 1 + 1 + 1 + SIGNATURE_LENGTH };                         // tag(1) + length(1) + padding(1) + content(64)

enum { certificate_length =  tbs_certificate_length + signature_algorithm_length + signature_value_length + 3 +1 };

enum { asn1_privatekey_version_length = 1 + 1 + 1 };                                    // tag(1) + length(1) + content(1)
enum { asn1_privatekeyfield_length = 1 + 1 + RAW_PRIVATE_KEY_LENGTH };                   // tag(1) + length(1) + RAW_PRIVATE_KEY_LENGTH
enum { p256_keyid_length = 1 + 1 + prime256v1_oid_length };                             // tag(1) + length(1) + prime256v1_oid_length
enum { asn1_privatekey_pubkeycopy_length = 1 + 1 + pubkey_bitstring_length };                             // tag(1) + length(1) + pubkey_bitstring_length
enum { asn1_privatekey_length = 1 + 1 + asn1_privatekey_version_length + asn1_privatekeyfield_length + p256_keyid_length + asn1_privatekey_pubkeycopy_length };


size_t
get_certificate_length();

size_t
get_asn1privatekey_length();

void
set_length(unsigned char **current_loc,
           size_t length);

void
build_x509_skeleton(unsigned char *certificate_out,
                    unsigned char **pubkey_location,
                    unsigned char **signature_location,
                    unsigned char **signature_input_location,
                    size_t *signature_input_length,
                    const char *common_name);

void
build_asn1_key_skeleton(unsigned char *asn1_out,
                        unsigned char **privkey_location,
                        unsigned char **pubkey_location);

void
set_as_sequence(unsigned char **current_loc);

void
set_as_set(unsigned char **current_loc);

void
build_tbs_certificate(unsigned char **current_loc,
                      unsigned char **pubkey_location,
                      const char *common_name);

void
build_publickey(unsigned char **current_loc, unsigned char **pubkey_location);

void
build_signature_algorithm(unsigned char **current_loc);

void
build_privatekey_algorithm(unsigned char **current_loc);

void
build_privatekey_publickeycopy(unsigned char **current_loc,
                               unsigned char **pubkey_location);

void
build_serial_number(unsigned char **current_loc);

void
build_name(unsigned char **current_loc,
           const char *common_name);

void
build_validity(unsigned char **current_loc);

void
build_subjectpublickeyinfo(unsigned char **current_loc, unsigned char **pubkey_location);

void
get_validity_times(char *not_before_time, char *not_after_time);

void
build_privkey_version(unsigned char **current_loc);

void
build_curve(unsigned char **current_loc);

#ifdef __cplusplus
}
#endif

#endif
