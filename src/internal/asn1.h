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

size_t
get_certificate_length();

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
                        unsigned char **privkey_location);

void
set_as_sequence(unsigned char **current_loc);

void
set_as_set(unsigned char **current_loc);

void
build_tbs_certificate(unsigned char **current_loc,
                      unsigned char **pubkey_location,
                      const char *common_name);

void
build_signature_algorithm(unsigned char **current_loc);

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
build_curveprivatekey(unsigned char **current_loc,
                      unsigned char **privatekey_location);

#ifdef __cplusplus
}
#endif

#endif

