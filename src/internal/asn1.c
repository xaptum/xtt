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

#include "asn1.h"

#include <xtt/crypto_wrapper.h>

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

const unsigned char SEQUENCE_TAG = 0x30;
const unsigned char SET_TAG = 0x31;
const unsigned char INTEGER_TAG = 0x02;
const unsigned char OBJECTIDENTIFIER_TAG = 0x06;
const unsigned char UTCTIME_TAG = 0x17;
const unsigned char BITSTRING_TAG = 0x03;
const unsigned char OCTETSTRING_TAG = 0x04;

const unsigned char COMMONNAME_OID[] = {0x55, 0x04, 0x03};
const unsigned char ED25519_OID[] = {0x2B, 0x65, 0x70};

const unsigned char ONEASYMMETRICKEY_VERSION = 0x00;

const unsigned char UTF8STRING_ATTRTYPE = 0x0C;

const int VALIDITY_YEARS = 1;

enum { UTC_LENGTH = 13 };                                                               // YYMMDDhhssmm'Z'
enum { NAME_LENGTH = 32 };
enum { RAW_PRIVATE_KEY_LENGTH = 32 };
enum { PUBLIC_KEY_LENGTH = 32 };
enum { SIGNATURE_LENGTH = 64 };

enum { serial_num_length = 1 + 1 + 20 };                                                // tag(1) + length(1) + content(20)

enum { ed25519_oid_length = 1 + 1 + 3 };                                                // tag(1) + length(1) + content(3)
enum { ed25519_algid_length = 1 + 1 + ed25519_oid_length };                             // tag(1) + length(1) + ed25519_oid_length

enum { name_string_length = 1 + 1 + NAME_LENGTH };                                               // tag(1) + length(1) + content(32)
enum { name_oid_length = 1 + 1 + 3 };                                                   // tag(1) + length(1) + content(3)
enum { name_attr_tandv_length = 1 + 1 + name_oid_length + name_string_length };         // tag(1) + length(1) + name_oid_length + name_string_length
enum { rdn_length = 1 + 1 + name_attr_tandv_length };                                   // tag(1) + length(1) + name_attr_tandv_length
enum { name_length = 1 + 1 + rdn_length };                                              // tag(1) + length(1) + rdn_length

enum { utctime_length = 1 + 1 + UTC_LENGTH };                                           // tag(1) + length(1) + content(13) 'YYMMDDhhssmmZ'
enum { validity_length = 1 + 1 + 2*utctime_length };                                    // tag(1) + length(1) + 2*utctime_length (one for notBefore, other for notAfter)

enum { pubkey_bitstring_length = 1 + 1 + 1 + PUBLIC_KEY_LENGTH };                       // tag(1) + length(1) + padding(1) + content(32)
enum { subjectpublickeyinfo_length = 1 + 1 + ed25519_algid_length + pubkey_bitstring_length };    // tag(1) + length(1) + ed25519_algid_length + pubkey_bitstring_length

enum { tbs_certificate_length = 1 + 2 + serial_num_length + ed25519_algid_length + name_length + validity_length + name_length + subjectpublickeyinfo_length };

enum { signature_algorithm_length = ed25519_algid_length }; 

enum { signature_value_length = 1 + 1 + 1 + SIGNATURE_LENGTH };                         // tag(1) + length(1) + padding(1) + content(64)

enum { certificate_length = 1 + 3 + tbs_certificate_length + signature_algorithm_length + signature_value_length };

enum { asn1_privatekey_version_length = 1 + 1 + 1 };                                    // tag(1) + length(1) + content(1)
enum { asn1_curveprivatekey_length = 1 + 1 + RAW_PRIVATE_KEY_LENGTH };
enum { asn1_privatekey_total_length = 1 + 1 + asn1_curveprivatekey_length };            // tag(1) + length(1) + asn1_curveprivatekey_length
enum { asn1_privatekey_length = 1 + 1 + asn1_privatekey_version_length + ed25519_algid_length + asn1_privatekey_total_length };

size_t
get_certificate_length()
{
    return certificate_length;
}

void
build_x509_skeleton(unsigned char *certificate_out,
                    unsigned char **pubkey_location,
                    unsigned char **signature_location,
                    unsigned char **signature_input_location,
                    size_t *signature_input_length,
                    const char *common_name)
{
    unsigned char *current_loc = certificate_out;

    set_as_sequence(&current_loc);
    set_length(&current_loc, certificate_length - 1 - 3);

    *signature_input_location = current_loc;
    *signature_input_length = tbs_certificate_length;

    build_tbs_certificate(&current_loc, pubkey_location, common_name);

    build_signature_algorithm(&current_loc);

    *current_loc = BITSTRING_TAG;
    current_loc += 1;
    set_length(&current_loc, signature_value_length - 1 - 1);

    // Add a 0x00, to indicate we didn't need to pad (signature is always a multiple of 8bits)
    *current_loc = 0x00;
    current_loc += 1;

    *signature_location = current_loc;
}

void
build_privkey_version(unsigned char **current_loc)
{
    **current_loc = INTEGER_TAG;
    *current_loc += 1;
    set_length(current_loc, 1);

    **current_loc = ONEASYMMETRICKEY_VERSION;

    *current_loc += 1;
}

void
build_curveprivatekey(unsigned char **current_loc,
                      unsigned char **privatekey_location)
{
    **current_loc = OCTETSTRING_TAG;
    *current_loc += 1;
    set_length(current_loc, asn1_privatekey_total_length - 1 - 1);

    **current_loc = OCTETSTRING_TAG;
    *current_loc += 1;
    set_length(current_loc, asn1_curveprivatekey_length - 1 - 1);

    *privatekey_location = *current_loc;
}

void
build_asn1_key_skeleton(unsigned char *asn1_out,
                        unsigned char **privkey_location)
{
    unsigned char *current_loc = asn1_out;

    set_as_sequence(&current_loc);
    set_length(&current_loc, asn1_privatekey_length - 1 - 1);

    build_privkey_version(&current_loc);

    build_signature_algorithm(&current_loc);

    build_curveprivatekey(&current_loc, privkey_location);
}

void
set_as_sequence(unsigned char **current_loc)
{
    **current_loc = SEQUENCE_TAG;
    *current_loc += 1;
}

void
set_as_set(unsigned char **current_loc)
{
    **current_loc = SET_TAG;
    *current_loc += 1;
}

void
build_tbs_certificate(unsigned char **current_loc,
                      unsigned char **pubkey_location,
                      const char *common_name)
{
    set_as_sequence(current_loc);
    set_length(current_loc, tbs_certificate_length - 1 - 2);

    build_serial_number(current_loc);

    build_signature_algorithm(current_loc);

    build_name(current_loc, common_name);    // issuer name

    build_validity(current_loc);

    build_name(current_loc, common_name);    // subject name

    build_subjectpublickeyinfo(current_loc, pubkey_location);
}

void
set_length(unsigned char **current_loc,
           size_t length)
{
    if (length < 127) {
        **current_loc = length;
        *current_loc += 1;
    } else if (length < UINT8_MAX) {
        (*current_loc)[0] = 0x80 + 1;   // Set msb to 1, to indicate a long format, and add one for the one next block
        (*current_loc)[1] = length;
        *current_loc += 2;
    } else if (length < UINT16_MAX) {
        (*current_loc)[0] = 0x80 + 2;   // Set msb to 1, to indicate a long format, and add two for the two next blocks
        (*current_loc)[1] = length >> 8;
        (*current_loc)[2] = length & 0xFF;
        *current_loc += 3;
    } else {
        // None of our lengths should require more than 2 bytes to represent
        exit(1);
    }
}

void
build_signature_algorithm(unsigned char **current_loc)
{
    set_as_sequence(current_loc);
    set_length(current_loc, ed25519_algid_length - 1 - 1);

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, ed25519_oid_length - 1 - 1);

    memcpy(*current_loc, ED25519_OID, 3);
    *current_loc += 3;
}

void
build_serial_number(unsigned char **current_loc)
{
    const size_t len = serial_num_length - 1 - 1;

    **current_loc = INTEGER_TAG;
    *current_loc += 1;
    set_length(current_loc, len);

    assert(len == 20);
    // Nb. We're only generating 19 bytes of randomness
    xtt_crypto_get_random(*current_loc, len-1);
    (*current_loc)[0] = 0x00;   // clear MSB, to ensure it's not a signed integer

    *current_loc += len;
}

void
build_name(unsigned char **current_loc,
           const char *common_name)
{
    set_as_sequence(current_loc);
    set_length(current_loc, name_length - 1 - 1);

    set_as_set(current_loc);
    set_length(current_loc, rdn_length - 1 - 1);

    set_as_sequence(current_loc);
    set_length(current_loc, name_attr_tandv_length - 1 - 1);

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, name_oid_length - 1 - 1);
    memcpy(*current_loc, COMMONNAME_OID, 3);
    *current_loc += 3;

    **current_loc = UTF8STRING_ATTRTYPE;
    *current_loc += 1;
    set_length(current_loc, NAME_LENGTH);
    memcpy(*current_loc, common_name, NAME_LENGTH);
    *current_loc += NAME_LENGTH;
}

void
build_validity(unsigned char **current_loc)
{
    set_as_sequence(current_loc);
    set_length(current_loc, validity_length - 1 - 1);

    char not_before_time[14];
    assert(sizeof(not_before_time) == UTC_LENGTH + 1);      // for the null-terminator
    char not_after_time[14];
    assert(sizeof(not_after_time) == UTC_LENGTH + 1);      // for the null-terminator
    get_validity_times(not_before_time, not_after_time);

    **current_loc = UTCTIME_TAG;
    *current_loc += 1;
    set_length(current_loc, utctime_length - 1 - 1);
    memcpy(*current_loc, not_before_time, UTC_LENGTH);
    *current_loc += UTC_LENGTH;

    **current_loc = UTCTIME_TAG;
    *current_loc += 1;
    set_length(current_loc, utctime_length - 1 - 1);
    memcpy(*current_loc, not_after_time, UTC_LENGTH);
    *current_loc += UTC_LENGTH;
}

void
build_subjectpublickeyinfo(unsigned char **current_loc, unsigned char **pubkey_location)
{
    set_as_sequence(current_loc);
    set_length(current_loc, subjectpublickeyinfo_length - 1 - 1);

    build_signature_algorithm(current_loc);

    **current_loc = BITSTRING_TAG;
    *current_loc += 1;
    set_length(current_loc, pubkey_bitstring_length - 1 - 1);

    // Add a 0x00, to indicate we didn't need to pad (pub key is always a multiple of 8bits)
    **current_loc = 0x00;
    *current_loc += 1;

    *pubkey_location = *current_loc;

    // Increment, to make space for pub key (caller will copy it in)
    *current_loc += sizeof(xtt_ed25519_pub_key);
}

void
get_validity_times(char *not_before_time, char *not_after_time)
{
    time_t now_timet = time(NULL);
    struct tm *now = gmtime(&now_timet);

    snprintf(not_before_time,
             UTC_LENGTH + 1,
             "%02d%02d%02d000000Z",
             now->tm_year - 100,
             now->tm_mon + 1,
             now->tm_mday);

    snprintf(not_after_time,
             UTC_LENGTH + 1,
             "%02d%02d%02d000000Z",
             now->tm_year - 100 + VALIDITY_YEARS,
             now->tm_mon + 1,
             now->tm_mday);
}
